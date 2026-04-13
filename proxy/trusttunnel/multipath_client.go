package trusttunnel

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/net/http2"
)

type trustTunnelMultipathOpenResult struct {
	attempt  trustTunnelServerAttempt
	response *trustTunnelMultipathOpenResponse
	conn     io.ReadWriteCloser
}

func connectHTTP2WithResponse(rawConn stat.Connection, req *http.Request) (*http.Response, io.ReadWriteCloser, error) {
	pr, pw := io.Pipe()
	req.Body = pr

	t := http2.Transport{}
	h2clientConn, err := t.NewClientConn(rawConn)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, nil, err
	}

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		_ = rawConn.Close()
		return nil, nil, errors.New("trusttunnel CONNECT failed with status ", resp.StatusCode, ": ", string(body))
	}

	return resp, newHTTP2Conn(rawConn, pw, resp.Body), nil
}

func (c *Client) processMultipathTCP(
	ctx context.Context,
	link *transport.Link,
	dialer internet.Dialer,
	target xnet.Destination,
	attempts []trustTunnelServerAttempt,
	tlsHandledByStreamSettings bool,
) error {
	if target.Network != xnet.Network_TCP {
		return errors.New("trusttunnel multipath currently supports TCP only").AtError()
	}

	multipath := c.config.GetMultipath()
	if multipath == nil || !multipath.GetEnabled() {
		return errors.New("trusttunnel multipath is disabled").AtError()
	}

	targetHost := target.NetAddr()
	if targetHost == "" {
		return errors.New("invalid multipath target address")
	}

	minChannels := multipath.GetMinChannels()
	if minChannels == 0 {
		minChannels = 2
	}
	uniqueAttempts := c.uniqueMultipathAttempts(attempts)
	if len(uniqueAttempts) < int(minChannels) {
		return errors.New("trusttunnel multipath needs at least ", minChannels, " distinct endpoints after runtime resolution")
	}

	openResult, err := c.openMultipathPrimaryChannel(ctx, dialer, uniqueAttempts, targetHost, tlsHandledByStreamSettings)
	if err != nil {
		return err
	}

	attachSecret, err := trustTunnelMultipathDecodeAttachSecret(openResult.response.AttachSecret)
	if err != nil {
		_ = openResult.conn.Close()
		return err
	}

	sessionState := newTrustTunnelMultipathSession(trustTunnelMultipathSessionOptions{
		ID:            openResult.response.SessionID,
		Target:        target,
		TargetHost:    targetHost,
		MinChannels:   openResult.response.MinChannels,
		MaxChannels:   openResult.response.MaxChannels,
		Scheduler:     openResult.response.Scheduler,
		Strict:        openResult.response.Strict,
		AttachTimeout: time.Duration(multipath.GetAttachTimeoutSecs()) * time.Second,
		AttachSecret:  attachSecret,
		ReorderWindow: int(multipath.GetReorderWindowBytes()),
		GapTimeout:    time.Duration(multipath.GetReorderGapTimeoutMs()) * time.Millisecond,
	})

	cleanupSession := true
	defer func() {
		if cleanupSession {
			sessionState.Close(nil)
		}
	}()

	if err := sessionState.AddChannel(&trustTunnelMultipathChannel{
		id:       openResult.response.PrimaryChannelID,
		endpoint: openResult.attempt.server.Destination.NetAddr(),
		stream:   openResult.conn,
	}); err != nil {
		_ = openResult.conn.Close()
		return err
	}

	nextChannelID := openResult.response.PrimaryChannelID + 1
	connected := 1
	for _, attempt := range uniqueAttempts {
		if connected >= int(minChannels) {
			break
		}
		if attempt.index == openResult.attempt.index {
			continue
		}

		conn, err := c.openMultipathSecondaryChannel(ctx, dialer, attempt, openResult.response.SessionID, openResult.response.AttachSecret, nextChannelID, targetHost, tlsHandledByStreamSettings)
		if err != nil {
			c.noteServerFailure(attempt.index)
			errors.LogWarning(ctx, "trusttunnel multipath attach failed for endpoint ", attempt.server.Destination.NetAddr(), ": ", err)
			continue
		}

		if err := sessionState.AddChannel(&trustTunnelMultipathChannel{
			id:       nextChannelID,
			endpoint: attempt.server.Destination.NetAddr(),
			stream:   conn,
		}); err != nil {
			_ = conn.Close()
			return err
		}

		c.noteServerSuccess(attempt.index)
		connected++
		nextChannelID++
	}

	if connected < int(minChannels) {
		return errors.New("trusttunnel multipath could not establish required channel quorum: got ", connected, ", want ", minChannels).AtWarning()
	}

	stream, err := newTrustTunnelMultipathStream(sessionState)
	if err != nil {
		return err
	}
	defer stream.Close()

	cleanupSession = false
	return runTrustTunnelStreamTunnel(ctx, link, stream)
}

func (c *Client) uniqueMultipathAttempts(attempts []trustTunnelServerAttempt) []trustTunnelServerAttempt {
	seen := make(map[string]struct{}, len(attempts))
	unique := make([]trustTunnelServerAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.server == nil {
			continue
		}
		key := strings.TrimSpace(attempt.server.Destination.NetAddr())
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, attempt)
	}
	return unique
}

func (c *Client) openMultipathPrimaryChannel(
	ctx context.Context,
	dialer internet.Dialer,
	attempts []trustTunnelServerAttempt,
	targetHost string,
	tlsHandledByStreamSettings bool,
) (*trustTunnelMultipathOpenResult, error) {
	var lastErr error
	for _, attempt := range attempts {
		account, err := trustTunnelAccountFromServer(attempt.server)
		if err != nil {
			lastErr = err
			continue
		}

		req, err := buildTrustTunnelMultipathOpenRequest(targetHost, account, c.config.GetMultipath())
		if err != nil {
			return nil, err
		}

		resp, tunnelConn, err := c.connectMultipathHTTP2Tunnel(ctx, dialer, attempt.server, req, tlsHandledByStreamSettings)
		if err != nil {
			c.noteServerFailure(attempt.index)
			lastErr = err
			continue
		}

		openResp, err := parseTrustTunnelMultipathOpenResponse(resp)
		if err != nil {
			_ = tunnelConn.Close()
			lastErr = err
			continue
		}

		c.noteServerSuccess(attempt.index)
		return &trustTunnelMultipathOpenResult{
			attempt:  attempt,
			response: openResp,
			conn:     tunnelConn,
		}, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no target trusttunnel server found")
}

func (c *Client) openMultipathSecondaryChannel(
	ctx context.Context,
	dialer internet.Dialer,
	attempt trustTunnelServerAttempt,
	sessionID string,
	attachSecret string,
	channelID uint32,
	targetHost string,
	tlsHandledByStreamSettings bool,
) (io.ReadWriteCloser, error) {
	account, err := trustTunnelAccountFromServer(attempt.server)
	if err != nil {
		return nil, err
	}

	req, err := buildTrustTunnelMultipathAttachRequest(sessionID, attachSecret, channelID, targetHost, account)
	if err != nil {
		return nil, err
	}

	resp, tunnelConn, err := c.connectMultipathHTTP2Tunnel(ctx, dialer, attempt.server, req, tlsHandledByStreamSettings)
	if err != nil {
		return nil, err
	}
	if channelValue := strings.TrimSpace(resp.Header.Get(trustTunnelMultipathHeaderChannelID)); channelValue == "" {
		_ = tunnelConn.Close()
		return nil, errors.New("trusttunnel multipath attach response is missing channel id")
	}
	return tunnelConn, nil
}

func (c *Client) connectMultipathHTTP2Tunnel(
	ctx context.Context,
	dialer internet.Dialer,
	server *protocol.ServerSpec,
	req *http.Request,
	tlsHandledByStreamSettings bool,
) (*http.Response, io.ReadWriteCloser, error) {
	rawConn, err := dialer.Dial(ctx, server.Destination)
	if err != nil {
		return nil, nil, errors.New("failed to dial trusttunnel server").Base(err).AtWarning()
	}
	conn := rawConn.(stat.Connection)

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, nil, errors.New("failed to set deadline").Base(err).AtWarning()
	}

	securityState, err := trustTunnelClientSecurityState(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if !trustTunnelShouldUseHTTP2(securityState) {
		_ = conn.Close()
		return nil, nil, errors.New("trusttunnel multipath requires negotiated HTTP/2 over TLS").AtWarning()
	}
	if !securityState.UsesReality && !tlsHandledByStreamSettings {
		if err := verifyTrustTunnelTLS(securityState.PeerCertificates, c.config); err != nil {
			_ = conn.Close()
			return nil, nil, errors.New("trusttunnel TLS verification failed").Base(err).AtWarning()
		}
	}

	resp, tunnelConn, err := connectHTTP2WithResponse(conn, req)
	if err != nil {
		_ = conn.Close()
		return nil, nil, errors.New("failed to establish trusttunnel multipath CONNECT").Base(err).AtWarning()
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = tunnelConn.Close()
		return nil, nil, errors.New("failed to clear deadline").Base(err).AtWarning()
	}

	return resp, tunnelConn, nil
}
