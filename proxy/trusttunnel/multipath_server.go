package trusttunnel

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	trustTunnelMultipathUnsupportedProtoText = "trusttunnel multipath phase 2 control path supports HTTP/2 only"
)

func trustTunnelMultipathEndpointFromRequest(req *http.Request, cleanupConn stat.Connection) string {
	if cleanupConn != nil {
		if endpoint := trustTunnelSafeLocalAddrString(cleanupConn); endpoint != "" {
			return endpoint
		}
	}
	if req != nil {
		if localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(stdnet.Addr); ok && localAddr != nil {
			return localAddr.String()
		}
	}
	return ""
}

func trustTunnelSafeLocalAddrString(conn stat.Connection) (endpoint string) {
	if conn == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			endpoint = ""
		}
	}()
	if localAddr := conn.LocalAddr(); localAddr != nil {
		return localAddr.String()
	}
	return ""
}

func trustTunnelMultipathAttachFailureStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch {
	case strings.Contains(err.Error(), trustTunnelMultipathDuplicateChannelText),
		strings.Contains(err.Error(), trustTunnelMultipathChannelLimitText):
		return http.StatusConflict
	default:
		return http.StatusForbidden
	}
}

func (s *Server) serveMultipathControlRequest(proto string, ctx context.Context, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, user *protocol.MemoryUser, cleanupConn stat.Connection) bool {
	if !isTrustTunnelMultipathOpenHost(req.Host) && !isTrustTunnelMultipathAttachHost(req.Host) {
		return false
	}

	if !strings.EqualFold(proto, "H2") {
		writeH2Response(w, http.StatusNotImplemented, trustTunnelMultipathUnsupportedProtoText+"\n", nil)
		errors.LogInfo(ctx, trustTunnelMultipathUnsupportedProtoText)
		return true
	}

	if isTrustTunnelMultipathOpenHost(req.Host) {
		s.serveMultipathOpenRequest(ctx, w, req, dispatcher, user, cleanupConn)
		return true
	}

	s.serveMultipathAttachRequest(ctx, w, req, dispatcher, user, cleanupConn)
	return true
}

func (s *Server) serveMultipathOpenRequest(ctx context.Context, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, user *protocol.MemoryUser, cleanupConn stat.Connection) {
	openReq, err := parseTrustTunnelMultipathOpenRequest(req)
	if err != nil {
		writeH2Response(w, http.StatusBadRequest, "invalid multipath open request\n", nil)
		errors.LogInfoInner(ctx, err, "failed to parse trusttunnel multipath open request")
		return
	}
	if openReq.MinChannels < 2 {
		writeH2Response(w, http.StatusBadRequest, "multipath requires minChannels >= 2\n", nil)
		return
	}
	if openReq.MaxChannels < openReq.MinChannels {
		writeH2Response(w, http.StatusBadRequest, "multipath requires maxChannels >= minChannels\n", nil)
		return
	}

	sessionID, err := trustTunnelMultipathRandomToken(16)
	if err != nil {
		writeH2Response(w, http.StatusInternalServerError, "failed to allocate multipath session\n", nil)
		errors.LogWarningInner(ctx, err, "failed to allocate trusttunnel multipath session id")
		return
	}
	attachSecret, err := trustTunnelMultipathRandomSecret(32)
	if err != nil {
		writeH2Response(w, http.StatusInternalServerError, "failed to allocate multipath secret\n", nil)
		errors.LogWarningInner(ctx, err, "failed to allocate trusttunnel multipath attach secret")
		return
	}

	sessionState := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            sessionID,
		Target:        openReq.Target,
		TargetHost:    openReq.TargetHost,
		MinChannels:   openReq.MinChannels,
		MaxChannels:   openReq.MaxChannels,
		Scheduler:     openReq.Scheduler,
		Strict:        openReq.Strict,
		AttachTimeout: openReq.AttachTimeout,
		AttachSecret:  attachSecret,
	})
	stream := newTrustTunnelMultipathHTTP2Stream(w, req.Body)
	if err := sessionState.AddChannel(&trustTunnelMultipathChannel{
		id:       trustTunnelMultipathPrimaryChannelID,
		endpoint: trustTunnelMultipathEndpointFromRequest(req, cleanupConn),
		stream:   stream,
	}); err != nil {
		writeH2Response(w, http.StatusInternalServerError, "failed to register primary multipath channel\n", nil)
		errors.LogWarningInner(ctx, err, "failed to register trusttunnel multipath primary channel")
		return
	}
	s.multipathSessions.Add(sessionState)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   req.RemoteAddr,
		To:     openReq.Target,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "trusttunnel H2 multipath open accepted for ", openReq.Target, " session=", sessionID)

	h := w.Header()
	h.Set(trustTunnelMultipathHeaderSessionID, sessionID)
	h.Set(trustTunnelMultipathHeaderAttachSecret, sessionState.AttachSecretHeaderValue())
	h.Set(trustTunnelMultipathHeaderPrimaryChannelID, strconv.FormatUint(uint64(sessionState.PrimaryChannelID()), 10))
	h.Set(trustTunnelMultipathHeaderMinChannels, strconv.FormatUint(uint64(sessionState.minChannels), 10))
	h.Set(trustTunnelMultipathHeaderMaxChannels, strconv.FormatUint(uint64(sessionState.maxChannels), 10))
	h.Set(trustTunnelMultipathHeaderScheduler, trustTunnelMultipathSchedulerHeaderValue(sessionState.scheduler))
	h.Set(trustTunnelMultipathHeaderStrict, strconv.FormatBool(sessionState.strict))
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}

	s.startMultipathAttachDeadlineWatcher(ctx, sessionState)
	s.maybeStartMultipathServerSession(ctx, sessionState, dispatcher)
	s.waitForMultipathSession(ctx, sessionState)
}

func (s *Server) serveMultipathAttachRequest(ctx context.Context, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, user *protocol.MemoryUser, cleanupConn stat.Connection) {
	attachReq, err := parseTrustTunnelMultipathAttachRequest(req)
	if err != nil {
		writeH2Response(w, http.StatusBadRequest, "invalid multipath attach request\n", nil)
		errors.LogInfoInner(ctx, err, "failed to parse trusttunnel multipath attach request")
		return
	}

	sessionState, ok := s.multipathSessions.Get(attachReq.SessionID)
	if !ok {
		writeH2Response(w, http.StatusForbidden, "multipath attach rejected\n", nil)
		errors.LogInfo(ctx, "trusttunnel H2 multipath attach rejected: unknown session")
		return
	}

	if err := sessionState.AttachChannel(attachReq, trustTunnelMultipathEndpointFromRequest(req, cleanupConn), trustTunnelMultipathNow()); err != nil {
		writeH2Response(w, trustTunnelMultipathAttachFailureStatus(err), "multipath attach rejected\n", nil)
		errors.LogInfoInner(ctx, err, "trusttunnel H2 multipath attach rejected")
		return
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   req.RemoteAddr,
		To:     sessionState.target,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "trusttunnel H2 multipath attach accepted for ", sessionState.target, " session=", sessionState.ID(), " channel=", attachReq.ChannelID)

	h := w.Header()
	h.Set(trustTunnelMultipathHeaderSessionID, sessionState.ID())
	h.Set(trustTunnelMultipathHeaderChannelID, strconv.FormatUint(uint64(attachReq.ChannelID), 10))
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}

	if err := sessionState.SetChannelStream(attachReq.ChannelID, newTrustTunnelMultipathHTTP2Stream(w, req.Body)); err != nil {
		writeH2Response(w, http.StatusInternalServerError, "failed to finalize multipath attach\n", nil)
		errors.LogWarningInner(ctx, err, "failed to finalize trusttunnel multipath attach stream")
		return
	}

	s.maybeStartMultipathServerSession(ctx, sessionState, dispatcher)
	s.waitForMultipathSession(ctx, sessionState)
}

type trustTunnelMultipathHTTP2Stream struct {
	reader io.ReadCloser
	writer io.Writer
}

func newTrustTunnelMultipathHTTP2Stream(w http.ResponseWriter, reader io.ReadCloser) io.ReadWriteCloser {
	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	if reader == nil {
		reader = http.NoBody
	}
	return &trustTunnelMultipathHTTP2Stream{
		reader: reader,
		writer: &flushWriter{
			w: w,
			f: flusher,
		},
	}
}

func (s *trustTunnelMultipathHTTP2Stream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *trustTunnelMultipathHTTP2Stream) Write(p []byte) (int, error) {
	return s.writer.Write(p)
}

func (s *trustTunnelMultipathHTTP2Stream) Close() error {
	if s.reader != nil {
		return s.reader.Close()
	}
	return nil
}
