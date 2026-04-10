package trusttunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
)

const (
	trustTunnelMultipathOpenHost   = "_mptcp_open:0"
	trustTunnelMultipathAttachHost = "_mptcp_attach:0"

	trustTunnelMultipathHeaderTarget            = "X-TrustTunnel-Multipath-Target"
	trustTunnelMultipathHeaderMinChannels       = "X-TrustTunnel-Multipath-Min-Channels"
	trustTunnelMultipathHeaderMaxChannels       = "X-TrustTunnel-Multipath-Max-Channels"
	trustTunnelMultipathHeaderScheduler         = "X-TrustTunnel-Multipath-Scheduler"
	trustTunnelMultipathHeaderAttachTimeoutSecs = "X-TrustTunnel-Multipath-Attach-Timeout-Secs"
	trustTunnelMultipathHeaderStrict            = "X-TrustTunnel-Multipath-Strict"
	trustTunnelMultipathHeaderSessionID         = "X-TrustTunnel-Multipath-Session-Id"
	trustTunnelMultipathHeaderAttachSecret      = "X-TrustTunnel-Multipath-Attach-Secret"
	trustTunnelMultipathHeaderPrimaryChannelID  = "X-TrustTunnel-Multipath-Primary-Channel-Id"
	trustTunnelMultipathHeaderChannelID         = "X-TrustTunnel-Multipath-Channel-Id"
	trustTunnelMultipathHeaderChannelNonce      = "X-TrustTunnel-Multipath-Channel-Nonce"
	trustTunnelMultipathHeaderChannelTimestamp  = "X-TrustTunnel-Multipath-Channel-Timestamp"
	trustTunnelMultipathHeaderAttachProof       = "X-TrustTunnel-Multipath-Attach-Proof"
)

const (
	trustTunnelMultipathDefaultAttachTimeout = 5 * time.Second
	trustTunnelMultipathAttachSkewWindow     = 30 * time.Second
)

var trustTunnelMultipathNow = time.Now

type trustTunnelMultipathOpenRequest struct {
	Target        xnet.Destination
	TargetHost    string
	MinChannels   uint32
	MaxChannels   uint32
	Scheduler     MultipathScheduler
	AttachTimeout time.Duration
	Strict        bool
}

type trustTunnelMultipathOpenResponse struct {
	SessionID        string
	AttachSecret     string
	PrimaryChannelID uint32
	MinChannels      uint32
	MaxChannels      uint32
	Scheduler        MultipathScheduler
	Strict           bool
}

type trustTunnelMultipathAttachRequest struct {
	SessionID  string
	ChannelID  uint32
	TargetHost string
	Nonce      string
	Timestamp  time.Time
	Proof      string
}

func trustTunnelCanonicalizeMultipathTargetHost(targetHost string) (xnet.Destination, string, error) {
	target, err := http_proto.ParseHost(strings.TrimSpace(targetHost), xnet.Port(443))
	if err != nil {
		return xnet.Destination{}, "", errors.New("trusttunnel multipath target is invalid").Base(err)
	}
	return target, target.NetAddr(), nil
}

func isTrustTunnelMultipathOpenHost(host string) bool {
	switch strings.ToLower(host) {
	case "_mptcp_open", "_mptcp_open:0":
		return true
	default:
		return false
	}
}

func isTrustTunnelMultipathAttachHost(host string) bool {
	switch strings.ToLower(host) {
	case "_mptcp_attach", "_mptcp_attach:0":
		return true
	default:
		return false
	}
}

func buildTrustTunnelMultipathOpenRequest(targetHost string, account *MemoryAccount, multipath *MultipathConfig) (*http.Request, error) {
	req, err := buildConnectRequest(trustTunnelMultipathOpenHost, account)
	if err != nil {
		return nil, err
	}
	req.Header.Set(trustTunnelMultipathHeaderTarget, targetHost)

	if multipath == nil {
		return req, nil
	}

	minChannels := multipath.GetMinChannels()
	if minChannels == 0 {
		minChannels = 2
	}
	maxChannels := multipath.GetMaxChannels()
	if maxChannels == 0 {
		maxChannels = minChannels
	}
	scheduler := multipath.GetScheduler()
	if scheduler == MultipathScheduler_MULTIPATH_SCHEDULER_UNSPECIFIED {
		scheduler = MultipathScheduler_MULTIPATH_SCHEDULER_ROUND_ROBIN
	}

	req.Header.Set(trustTunnelMultipathHeaderMinChannels, strconv.FormatUint(uint64(minChannels), 10))
	req.Header.Set(trustTunnelMultipathHeaderMaxChannels, strconv.FormatUint(uint64(maxChannels), 10))
	req.Header.Set(trustTunnelMultipathHeaderScheduler, trustTunnelMultipathSchedulerHeaderValue(scheduler))
	if attachTimeoutSecs := multipath.GetAttachTimeoutSecs(); attachTimeoutSecs > 0 {
		req.Header.Set(trustTunnelMultipathHeaderAttachTimeoutSecs, strconv.FormatUint(uint64(attachTimeoutSecs), 10))
	}
	req.Header.Set(trustTunnelMultipathHeaderStrict, strconv.FormatBool(multipath.GetStrict()))
	return req, nil
}

func buildTrustTunnelMultipathAttachRequest(sessionID string, attachSecret string, channelID uint32, targetHost string, account *MemoryAccount) (*http.Request, error) {
	return buildTrustTunnelMultipathAttachRequestAt(sessionID, attachSecret, channelID, targetHost, account, trustTunnelMultipathNow(), "")
}

func buildTrustTunnelMultipathAttachRequestAt(sessionID string, attachSecret string, channelID uint32, targetHost string, account *MemoryAccount, now time.Time, nonce string) (*http.Request, error) {
	req, err := buildConnectRequest(trustTunnelMultipathAttachHost, account)
	if err != nil {
		return nil, err
	}
	if nonce == "" {
		nonce, err = trustTunnelMultipathRandomToken(16)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set(trustTunnelMultipathHeaderSessionID, sessionID)
	req.Header.Set(trustTunnelMultipathHeaderChannelID, strconv.FormatUint(uint64(channelID), 10))
	req.Header.Set(trustTunnelMultipathHeaderTarget, targetHost)
	req.Header.Set(trustTunnelMultipathHeaderChannelNonce, nonce)
	req.Header.Set(trustTunnelMultipathHeaderChannelTimestamp, strconv.FormatInt(now.Unix(), 10))
	req.Header.Set(trustTunnelMultipathHeaderAttachProof, trustTunnelMultipathComputeAttachProofString(attachSecret, sessionID, channelID, nonce, now.Unix(), targetHost))
	return req, nil
}

func parseTrustTunnelMultipathOpenRequest(req *http.Request) (*trustTunnelMultipathOpenRequest, error) {
	if req == nil {
		return nil, errors.New("trusttunnel multipath open request is nil")
	}

	targetHost := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderTarget))
	if targetHost == "" {
		return nil, errors.New("trusttunnel multipath open request is missing target header")
	}
	target, canonicalTargetHost, err := trustTunnelCanonicalizeMultipathTargetHost(targetHost)
	if err != nil {
		return nil, err
	}

	minChannels := uint32(2)
	if value := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderMinChannels)); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, errors.New("trusttunnel multipath open request has invalid minChannels").Base(err)
		}
		minChannels = uint32(parsed)
	}

	maxChannels := minChannels
	if value := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderMaxChannels)); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, errors.New("trusttunnel multipath open request has invalid maxChannels").Base(err)
		}
		maxChannels = uint32(parsed)
	}

	scheduler, err := parseTrustTunnelMultipathScheduler(req.Header.Get(trustTunnelMultipathHeaderScheduler))
	if err != nil {
		return nil, err
	}

	attachTimeout := trustTunnelMultipathDefaultAttachTimeout
	if value := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderAttachTimeoutSecs)); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, errors.New("trusttunnel multipath open request has invalid attachTimeoutSecs").Base(err)
		}
		if parsed > 0 {
			attachTimeout = time.Duration(parsed) * time.Second
		}
	}

	strict := true
	if value := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderStrict)); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, errors.New("trusttunnel multipath open request has invalid strict flag").Base(err)
		}
		strict = parsed
	}

	return &trustTunnelMultipathOpenRequest{
		Target:        target,
		TargetHost:    canonicalTargetHost,
		MinChannels:   minChannels,
		MaxChannels:   maxChannels,
		Scheduler:     scheduler,
		AttachTimeout: attachTimeout,
		Strict:        strict,
	}, nil
}

func parseTrustTunnelMultipathOpenResponse(resp *http.Response) (*trustTunnelMultipathOpenResponse, error) {
	if resp == nil {
		return nil, errors.New("trusttunnel multipath open response is nil")
	}

	parseUintHeader := func(name string) (uint32, error) {
		value := strings.TrimSpace(resp.Header.Get(name))
		if value == "" {
			return 0, errors.New("trusttunnel multipath open response is missing ", name)
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return 0, errors.New("trusttunnel multipath open response has invalid ", name).Base(err)
		}
		return uint32(parsed), nil
	}

	sessionID := strings.TrimSpace(resp.Header.Get(trustTunnelMultipathHeaderSessionID))
	attachSecret := strings.TrimSpace(resp.Header.Get(trustTunnelMultipathHeaderAttachSecret))
	if sessionID == "" || attachSecret == "" {
		return nil, errors.New("trusttunnel multipath open response is missing session headers")
	}
	primaryChannelID, err := parseUintHeader(trustTunnelMultipathHeaderPrimaryChannelID)
	if err != nil {
		return nil, err
	}
	minChannels, err := parseUintHeader(trustTunnelMultipathHeaderMinChannels)
	if err != nil {
		return nil, err
	}
	maxChannels, err := parseUintHeader(trustTunnelMultipathHeaderMaxChannels)
	if err != nil {
		return nil, err
	}
	scheduler, err := parseTrustTunnelMultipathScheduler(resp.Header.Get(trustTunnelMultipathHeaderScheduler))
	if err != nil {
		return nil, err
	}
	strict := true
	if value := strings.TrimSpace(resp.Header.Get(trustTunnelMultipathHeaderStrict)); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, errors.New("trusttunnel multipath open response has invalid strict flag").Base(err)
		}
		strict = parsed
	}

	return &trustTunnelMultipathOpenResponse{
		SessionID:        sessionID,
		AttachSecret:     attachSecret,
		PrimaryChannelID: primaryChannelID,
		MinChannels:      minChannels,
		MaxChannels:      maxChannels,
		Scheduler:        scheduler,
		Strict:           strict,
	}, nil
}

func parseTrustTunnelMultipathAttachRequest(req *http.Request) (*trustTunnelMultipathAttachRequest, error) {
	if req == nil {
		return nil, errors.New("trusttunnel multipath attach request is nil")
	}

	sessionID := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderSessionID))
	targetHost := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderTarget))
	nonce := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderChannelNonce))
	proof := strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderAttachProof))
	if sessionID == "" || targetHost == "" || nonce == "" || proof == "" {
		return nil, errors.New("trusttunnel multipath attach request is missing required headers")
	}

	_, canonicalTargetHost, err := trustTunnelCanonicalizeMultipathTargetHost(targetHost)
	if err != nil {
		return nil, err
	}

	channelID, err := strconv.ParseUint(strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderChannelID)), 10, 32)
	if err != nil || channelID == 0 {
		return nil, errors.New("trusttunnel multipath attach request has invalid channel id").Base(err)
	}

	timestampUnix, err := strconv.ParseInt(strings.TrimSpace(req.Header.Get(trustTunnelMultipathHeaderChannelTimestamp)), 10, 64)
	if err != nil {
		return nil, errors.New("trusttunnel multipath attach request has invalid timestamp").Base(err)
	}

	return &trustTunnelMultipathAttachRequest{
		SessionID:  sessionID,
		ChannelID:  uint32(channelID),
		TargetHost: canonicalTargetHost,
		Nonce:      nonce,
		Timestamp:  time.Unix(timestampUnix, 0),
		Proof:      proof,
	}, nil
}

func trustTunnelMultipathRandomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("failed to read trusttunnel multipath randomness").Base(err)
	}
	return hex.EncodeToString(raw), nil
}

func trustTunnelMultipathRandomSecret(size int) ([]byte, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return nil, errors.New("failed to read trusttunnel multipath secret").Base(err)
	}
	return raw, nil
}

func trustTunnelMultipathAttachSecretHeaderValue(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(secret)
}

func trustTunnelMultipathDecodeAttachSecret(value string) ([]byte, error) {
	secret, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("invalid trusttunnel multipath attach secret").Base(err)
	}
	if len(secret) == 0 {
		return nil, errors.New("invalid trusttunnel multipath attach secret: empty")
	}
	return secret, nil
}

func trustTunnelMultipathComputeAttachProof(secret []byte, sessionID string, channelID uint32, nonce string, timestampUnix int64, targetHost string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sessionID))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatUint(uint64(channelID), 10)))
	mac.Write([]byte{0})
	mac.Write([]byte(nonce))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(timestampUnix, 10)))
	mac.Write([]byte{0})
	mac.Write([]byte(targetHost))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func trustTunnelMultipathComputeAttachProofString(attachSecret string, sessionID string, channelID uint32, nonce string, timestampUnix int64, targetHost string) string {
	secret, err := trustTunnelMultipathDecodeAttachSecret(attachSecret)
	if err != nil {
		return ""
	}
	return trustTunnelMultipathComputeAttachProof(secret, sessionID, channelID, nonce, timestampUnix, targetHost)
}

func trustTunnelMultipathSchedulerHeaderValue(scheduler MultipathScheduler) string {
	switch scheduler {
	case MultipathScheduler_MULTIPATH_SCHEDULER_ROUND_ROBIN, MultipathScheduler_MULTIPATH_SCHEDULER_UNSPECIFIED:
		return "round_robin"
	default:
		return "round_robin"
	}
}

func parseTrustTunnelMultipathScheduler(value string) (MultipathScheduler, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "round_robin", "round-robin":
		return MultipathScheduler_MULTIPATH_SCHEDULER_ROUND_ROBIN, nil
	default:
		return MultipathScheduler_MULTIPATH_SCHEDULER_UNSPECIFIED, errors.New("unsupported trusttunnel multipath scheduler header: ", value)
	}
}
