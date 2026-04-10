package trusttunnel

import (
	"bufio"
	"bytes"
	"context"
	"io"
	stdnet "net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
	tcptransport "github.com/xtls/xray-core/transport/internet/tcp"
	"golang.org/x/net/http2"
)

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Server struct {
	config            *ServerConfig
	users             *UserStore
	policyManager     policy.Manager
	statsManager      stats.Manager
	connectionLimiter *trustTunnelConnectionLimiter
	multipathSessions *trustTunnelMultipathSessionRegistry
	newICMPSession    func(options trustTunnelICMPSessionOptions) (trustTunnelICMPHandler, error)
}

type bufferedConn struct {
	stat.Connection
	reader *bufio.Reader
	mu     sync.Mutex
	guard  *trustTunnelConnectionGuard
	auth   string
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) bindConnectionGuard(basicAuth string, acquire func() *trustTunnelConnectionGuard) error {
	if c == nil || acquire == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.guard != nil {
		if c.auth != basicAuth {
			return errors.New("trusttunnel authenticated HTTP/2 connection cannot switch credentials").AtWarning()
		}
		return nil
	}

	guard := acquire()
	if guard == nil {
		return errors.New("trusttunnel connection limit exceeded").AtInfo()
	}

	c.guard = guard
	c.auth = basicAuth
	return nil
}

func (c *bufferedConn) releaseConnectionGuard() {
	if c == nil {
		return
	}

	c.mu.Lock()
	guard := c.guard
	c.guard = nil
	c.auth = ""
	c.mu.Unlock()

	if guard != nil {
		guard.Release()
	}
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil && fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

type countedReadCloser struct {
	io.Reader
	io.Closer
}

type countedH3ResponseWriter struct {
	base   http.ResponseWriter
	writer io.Writer
	raw    bool
}

func (w *countedH3ResponseWriter) Header() http.Header {
	return w.base.Header()
}

func (w *countedH3ResponseWriter) WriteHeader(statusCode int) {
	w.base.WriteHeader(statusCode)
}

func (w *countedH3ResponseWriter) Write(p []byte) (int, error) {
	if !w.raw {
		n, err := w.base.Write(p)
		if err == nil {
			if fl, ok := w.base.(http.Flusher); ok {
				fl.Flush()
			}
		}
		return n, err
	}

	n, err := w.writer.Write(p)
	if err == nil {
		if fl, ok := w.base.(http.Flusher); ok {
			fl.Flush()
		}
	}
	return n, err
}

func (w *countedH3ResponseWriter) Flush() {
	if fl, ok := w.base.(http.Flusher); ok {
		fl.Flush()
	}
}

func (w *countedH3ResponseWriter) enableRawTunnelWrites() {
	if w != nil {
		w.raw = true
	}
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	store := &UserStore{}
	memoryUsers := make([]*protocol.MemoryUser, 0, len(config.Users))

	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get trusttunnel user").Base(err).AtError()
		}
		if err := store.Add(u); err != nil {
			return nil, errors.New("failed to add trusttunnel user").Base(err).AtError()
		}
		memoryUsers = append(memoryUsers, u)
	}

	return &Server{
		config:            config,
		users:             store,
		policyManager:     v.GetFeature(policy.ManagerType()).(policy.Manager),
		statsManager:      v.GetFeature(stats.ManagerType()).(stats.Manager),
		connectionLimiter: newTrustTunnelConnectionLimiter(memoryUsers, config.GetDefaultMaxHttp2ConnsPerClient(), config.GetDefaultMaxHttp3ConnsPerClient()),
		multipathSessions: newTrustTunnelMultipathSessionRegistry(),
	}, nil
}

func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	_ = ctx
	return s.users.Add(u)
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	_ = ctx
	return s.users.Del(email)
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	_ = ctx
	return s.users.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	_ = ctx
	return s.users.GetAll()
}

func (s *Server) GetUsersCount(ctx context.Context) int64 {
	_ = ctx
	return s.users.GetCount()
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func (s *Server) ListenerContext(ctx context.Context) context.Context {
	ctx = tcptransport.ContextWithTrustTunnelServerTimeouts(ctx, tcptransport.TrustTunnelServerTimeouts{
		TLSHandshakeTimeout:   s.config.tlsHandshakeTimeout(),
		ClientListenerTimeout: s.config.clientListenerTimeout(),
	})
	return tcptransport.ContextWithTrustTunnelServerTransportHints(ctx, tcptransport.TrustTunnelServerTransportHints{
		WantsHTTP3: trustTunnelServerWantsHTTP3(s.config.GetTransports()),
	})
}

func trustTunnelServerWantsHTTP3(transports []TransportProtocol) bool {
	for _, transport := range transports {
		if transport == TransportProtocol_HTTP3 {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	nerr, ok := errors.Cause(err).(net.Error)
	return ok && nerr.Timeout()
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	clientRandom := trustTunnelClientRandomFromConn(conn)
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "trusttunnel"
		inbound.CanSpliceCopy = 2
	}

	if h3conn, ok := any(conn).(tcptransport.HTTP3RequestConn); ok {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			errors.LogDebugInner(ctx, err, "failed to clear read deadline")
		}
		return s.processHTTP3(ctx, h3conn, conn, dispatcher, inbound)
	}

	if h3conn, ok := stat.TryUnwrapStatsConn(conn).(tcptransport.HTTP3RequestConn); ok {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			errors.LogDebugInner(ctx, err, "failed to clear read deadline")
		}
		return s.processHTTP3(ctx, h3conn, conn, dispatcher, inbound)
	}

	negotiatedProto := trustTunnelNegotiatedProtocol(conn)
	var h2PrefaceAbortTimer *time.Timer
	if strings.EqualFold(negotiatedProto, "h2") {
		h2PrefaceAbortTimer = startTrustTunnelConnAbortTimer(conn, s.config.clientListenerTimeout())
	}

	if err := conn.SetReadDeadline(time.Now().Add(s.config.clientListenerTimeout())); err != nil {
		errors.LogInfoInner(ctx, err, "failed to set read deadline")
	}

	reader := bufio.NewReaderSize(conn, 64*1024)

	preface, err := reader.Peek(len(h2ClientPreface))
	if negotiatedProto == "" {
		negotiatedProto = trustTunnelNegotiatedProtocol(conn)
	}
	if err == nil && bytes.Equal(preface, []byte(h2ClientPreface)) {
		if h2PrefaceAbortTimer != nil {
			h2PrefaceAbortTimer.Stop()
		}
		if _, err := reader.Discard(len(h2ClientPreface)); err != nil {
			return errors.New("failed to discard http2 preface").Base(err).AtWarning()
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			errors.LogDebugInner(ctx, err, "failed to clear read deadline")
		}
		return s.processHTTP2(ctx, &bufferedConn{Connection: conn, reader: reader}, dispatcher, inbound, clientRandom)
	}

	if strings.EqualFold(negotiatedProto, "h2") {
		if h2PrefaceAbortTimer != nil {
			h2PrefaceAbortTimer.Stop()
		}
		if err == nil {
			return errors.New("invalid trusttunnel http2 client preface").AtWarning()
		}

		trace := errors.New("failed to read trusttunnel http2 client preface").Base(err)
		if errors.Cause(err) != io.EOF && !isTimeout(errors.Cause(err)) {
			trace = trace.AtWarning()
		}
		return trace
	}

	if err != nil {
		if h2PrefaceAbortTimer != nil {
			h2PrefaceAbortTimer.Stop()
		}
		trace := errors.New("failed to read trusttunnel request").Base(err)
		if errors.Cause(err) != io.EOF && !isTimeout(errors.Cause(err)) {
			trace = trace.AtWarning()
		}
		return trace
	}

	return s.processHTTP1(ctx, conn, reader, dispatcher, inbound, clientRandom)
}

func startTrustTunnelConnAbortTimer(conn stat.Connection, timeout time.Duration) *time.Timer {
	if conn == nil || timeout <= 0 {
		return nil
	}
	return time.AfterFunc(timeout, func() {
		_ = forceCloseTrustTunnelConn(conn)
	})
}

func forceCloseTrustTunnelConn(conn stdnet.Conn) error {
	if conn == nil {
		return nil
	}

	if counterConn, ok := conn.(*stat.CounterConnection); ok {
		conn = counterConn.Connection
	}

	if rawConn, ok := conn.(interface{ NetConn() stdnet.Conn }); ok {
		return rawConn.NetConn().Close()
	}

	return conn.Close()
}

func trustTunnelBasicAuthFromUser(user *protocol.MemoryUser) string {
	if user == nil {
		return ""
	}
	acc, ok := user.Account.(*MemoryAccount)
	if !ok || acc == nil {
		return ""
	}
	return acc.BasicAuth
}

func (s *Server) acquireRequestConnectionGuard(user *protocol.MemoryUser, proto string, cleanupConn stat.Connection) (func(), error) {
	if s.connectionLimiter == nil {
		return func() {}, nil
	}

	basicAuth := trustTunnelBasicAuthFromUser(user)
	if basicAuth == "" {
		return nil, errors.New("trusttunnel authenticated user is missing connection limit key").AtWarning()
	}

	protocol := trustTunnelConnectionProtocolFromLabel(proto)
	if proto == "H2" {
		if conn, ok := cleanupConn.(*bufferedConn); ok {
			if err := conn.bindConnectionGuard(basicAuth, func() *trustTunnelConnectionGuard {
				return s.connectionLimiter.tryAcquire(basicAuth, protocol)
			}); err != nil {
				return nil, err
			}
			return func() {}, nil
		}
	}

	guard := s.connectionLimiter.tryAcquire(basicAuth, protocol)
	if guard == nil {
		return nil, errors.New("trusttunnel connection limit exceeded").AtInfo()
	}
	return guard.Release, nil
}

func trustTunnelLogRejectedConnection(ctx context.Context, from interface{}, to string, user *protocol.MemoryUser, reason string) {
	email := ""
	if user != nil {
		email = user.Email
	}
	log.Record(&log.AccessMessage{
		From:   from,
		To:     to,
		Status: log.AccessRejected,
		Reason: errors.New(reason),
		Email:  email,
	})
	errors.LogInfo(ctx, reason)
}

func trustTunnelConnectionRejection(err error) (int, string) {
	if err != nil && strings.Contains(err.Error(), "cannot switch credentials") {
		return http.StatusBadRequest, "authenticated HTTP/2 connection cannot switch credentials\n"
	}
	return http.StatusTooManyRequests, "connection limit exceeded\n"
}

func (s *Server) processHTTP3(ctx context.Context, h3conn tcptransport.HTTP3RequestConn, conn stat.Connection, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound) error {
	rawStream := h3conn.H3Stream()
	if rawStream == nil {
		return errors.New("trusttunnel H3 raw stream is unavailable").AtWarning()
	}

	req := &http.Request{
		Method:     h3conn.H3Method(),
		Host:       h3conn.H3Host(),
		Header:     h3conn.H3Header(),
		Body:       &countedReadCloser{Reader: rawStream, Closer: h3conn},
		RemoteAddr: h3conn.RemoteAddr().String(),
	}
	rw := &countedH3ResponseWriter{
		base:   h3conn,
		writer: rawStream,
	}

	s.serveHTTPConnectRequest("H3", ctx, rw, req.WithContext(ctx), dispatcher, inboundTemplate, h3conn.H3ClientRandom(), nil)
	return nil
}

func (s *Server) processHTTP1(ctx context.Context, conn stat.Connection, reader *bufio.Reader, dispatcher routing.Dispatcher, inbound *session.Inbound, clientRandom string) error {
Start:
	if err := conn.SetReadDeadline(time.Now().Add(s.config.clientListenerTimeout())); err != nil {
		errors.LogDebugInner(ctx, err, "failed to set trusttunnel H1 client listener deadline")
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		trace := errors.New("failed to read trusttunnel request").Base(err)
		if errors.Cause(err) != io.EOF && !isTimeout(errors.Cause(err)) {
			trace = trace.AtWarning()
		}
		return trace
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		errors.LogDebugInner(ctx, err, "failed to clear read deadline")
	}

	if !strings.EqualFold(req.Method, http.MethodConnect) {
		writePlainResponse(conn, http.StatusMethodNotAllowed, "Method Not Allowed", "trusttunnel supports CONNECT only\n", map[string]string{
			"Connection": "close",
		})
		return errors.New("trusttunnel unsupported method: ", req.Method).AtWarning()
	}

	authHeader := req.Header.Get("Proxy-Authorization")
	user := s.users.GetByBasicAuth(authHeader)
	if user == nil {
		statusCode := int(s.config.GetAuthFailureStatusCode())
		if statusCode == 0 {
			statusCode = http.StatusProxyAuthRequired
		}

		headers := map[string]string{
			"Connection": "close",
		}
		if statusCode == http.StatusProxyAuthRequired {
			headers["Proxy-Authenticate"] = `Basic realm="trusttunnel"`
		}

		writePlainResponse(conn, statusCode, http.StatusText(statusCode), "authentication failed\n", headers)

		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     req.Host,
			Status: log.AccessRejected,
			Reason: errors.New("trusttunnel authentication failed"),
		})

		return errors.New("trusttunnel authentication failed").AtWarning()
	}

	if inbound != nil {
		inbound.User = user
	}

	ctx = attachTrustTunnelClientRandom(ctx, clientRandom)
	if clientRandom != "" {
		errors.LogDebug(ctx, "trusttunnel client_random=", clientRandom)
	}

	allow, reason := isTrustTunnelAllowed(s.config.GetRules(), conn.RemoteAddr().String(), clientRandom)
	if reason != "" {
		errors.LogDebug(ctx, reason)
	}
	if !allow {
		writePlainResponse(conn, http.StatusForbidden, "Forbidden", "connection rejected by rule\n", map[string]string{
			"Connection": "close",
		})
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     req.Host,
			Status: log.AccessRejected,
			Reason: errors.New(reason),
			Email:  user.Email,
		})
		return errors.New(reason).AtInfo()
	}

	if isTrustTunnelHealthcheckHost(req.Host) {
		errors.LogInfo(ctx, "trusttunnel H1 health-check accepted")
		writePlainResponse(conn, http.StatusOK, http.StatusText(http.StatusOK), "", map[string]string{
			"Connection": "close",
		})
		return nil
	}

	if isTrustTunnelUDPHost(req.Host) {
		if !s.config.GetEnableUdp() {
			writePlainResponse(conn, http.StatusForbidden, "Forbidden", "udp is disabled\n", map[string]string{
				"Connection": "close",
			})
			return nil
		}

		writePlainResponse(conn, http.StatusBadRequest, "Bad Request", "udp mux requires HTTP/2 or HTTP/3\n", map[string]string{
			"Connection": "close",
		})
		errors.LogInfo(ctx, "trusttunnel H1 UDP pseudo-host rejected: requires H2/H3")
		return nil
	}

	if isTrustTunnelICMPHost(req.Host) {
		writePlainResponse(conn, http.StatusNotImplemented, "Not Implemented", "icmp is not implemented\n", map[string]string{
			"Connection": "close",
		})
		errors.LogInfo(ctx, "trusttunnel H1 ICMP pseudo-host reached but is not implemented")
		return nil
	}

	if isTrustTunnelMultipathOpenHost(req.Host) || isTrustTunnelMultipathAttachHost(req.Host) {
		writePlainResponse(conn, http.StatusNotImplemented, "Not Implemented", trustTunnelMultipathUnsupportedProtoText+"\n", map[string]string{
			"Connection": "close",
		})
		errors.LogInfo(ctx, trustTunnelMultipathUnsupportedProtoText)
		return nil
	}

	dest, err := http_proto.ParseHost(req.Host, net.Port(443))
	if err != nil {
		writePlainResponse(conn, http.StatusBadRequest, "Bad Request", "invalid CONNECT host\n", map[string]string{
			"Connection": "close",
		})
		return errors.New("malformed trusttunnel target: ", req.Host).Base(err).AtWarning()
	}

	releaseGuard, err := s.acquireRequestConnectionGuard(user, "H1", conn)
	if err != nil {
		statusCode, body := trustTunnelConnectionRejection(err)
		writePlainResponse(conn, statusCode, http.StatusText(statusCode), body, map[string]string{
			"Connection": "close",
		})
		trustTunnelLogRejectedConnection(ctx, conn.RemoteAddr(), req.Host, user, err.Error())
		return err
	}
	defer releaseGuard()

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})

	errors.LogInfo(ctx, "trusttunnel H1 CONNECT accepted for ", dest)

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return errors.New("failed to write trusttunnel CONNECT response").Base(err).AtWarning()
	}

	var linkReader buf.Reader = buf.NewReader(conn)
	if reader.Buffered() > 0 {
		payload, err := buf.ReadFrom(io.LimitReader(reader, int64(reader.Buffered())))
		if err != nil {
			return errors.New("failed to read buffered CONNECT payload").Base(err).AtWarning()
		}
		linkReader = &buf.BufferedReader{
			Reader: linkReader,
			Buffer: payload,
		}
	}

	if inbound != nil && inbound.CanSpliceCopy == 2 {
		inbound.CanSpliceCopy = 1
	}

	if err := s.dispatchConnectSession(ctx, dispatcher, dest, linkReader, buf.NewWriter(conn), conn); err != nil {
		return err
	}

	if strings.EqualFold(req.Header.Get("Proxy-Connection"), "keep-alive") {
		goto Start
	}

	return nil
}

func (s *Server) processHTTP2(ctx context.Context, conn *bufferedConn, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound, clientRandom string) error {
	done := make(chan struct{})
	defer conn.releaseConnectionGuard()

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.serveHTTP2Request(conn, w, req, dispatcher, inboundTemplate, clientRandom)
	})

	go func() {
		defer close(done)
		h2s := http2.Server{
			IdleTimeout: s.config.clientListenerTimeout(),
		}
		h2s.ServeConn(conn, &http2.ServeConnOpts{
			Context:          ctx,
			Handler:          handler,
			SawClientPreface: true,
		})
	}()

	<-done
	return nil
}

func (s *Server) serveHTTP2Request(conn stat.Connection, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound, clientRandom string) {
	s.serveHTTPConnectRequest("H2", req.Context(), w, req, dispatcher, inboundTemplate, clientRandom, conn)
}

func (s *Server) ServeHTTP3(ctx context.Context, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound) {
	s.serveHTTPConnectRequest("H3", ctx, w, req.WithContext(ctx), dispatcher, inboundTemplate, "", nil)
}

func isTrustTunnelHealthcheckHost(host string) bool {
	switch strings.ToLower(host) {
	case "_check", "_check:443":
		return true
	default:
		return false
	}
}

func isTrustTunnelICMPHost(host string) bool {
	switch strings.ToLower(host) {
	case "_icmp", "_icmp:0":
		return true
	default:
		return false
	}
}

func (s *Server) dispatchConnectSession(ctx context.Context, dispatcher routing.Dispatcher, dest net.Destination, input buf.Reader, output buf.Writer, cleanupTarget interface{}) error {
	abortInbound := func() {
		if conn, ok := cleanupTarget.(stdnet.Conn); ok {
			_ = forceCloseTrustTunnelConn(conn)
			return
		}
		_ = common.Interrupt(cleanupTarget)
	}

	dispatchCtx := ctx
	pinOnline := func() {}
	if establishTimeout := s.config.connectionEstablishmentTimeout(); establishTimeout > 0 {
		dispatchCtx = session.ContextWithTimeoutOnly(dispatchCtx, true)
		var cancel context.CancelFunc
		dispatchCtx, cancel = context.WithTimeout(dispatchCtx, establishTimeout)
		defer cancel()
		pinOnline = s.pinUserOnlineMap(ctx)
	}
	defer pinOnline()

	link, err := dispatcher.Dispatch(dispatchCtx, dest)
	if err != nil {
		abortInbound()
		return errors.New("failed to dispatch trusttunnel CONNECT").Base(err).AtWarning()
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var opts []buf.CopyOption
	if idleTimeout := s.config.tcpConnectionsTimeout(); idleTimeout > 0 {
		timer := signal.CancelAfterInactivity(sessionCtx, func() {
			cancel()
			abortInbound()
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}, idleTimeout)
		opts = append(opts, buf.UpdateActivity(timer))
	}

	requestDone := func() error {
		if err := buf.Copy(input, link.Writer, opts...); err != nil {
			return errors.New("failed to transport trusttunnel CONNECT request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		if err := buf.Copy(link.Reader, output, opts...); err != nil {
			return errors.New("failed to transport trusttunnel CONNECT response").Base(err)
		}
		return nil
	}

	requestDoneAndCloseWriter := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(sessionCtx, requestDoneAndCloseWriter, responseDone); err != nil {
		abortInbound()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("trusttunnel connection ends").Base(err)
	}

	return nil
}

func (s *Server) pinUserOnlineMap(ctx context.Context) func() {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" || inbound.Source.Address == nil || s.policyManager == nil || s.statsManager == nil {
		return func() {}
	}

	userPolicy := s.policyManager.ForLevel(inbound.User.Level)
	if !userPolicy.Stats.UserOnline {
		return func() {}
	}

	userIP := inbound.Source.Address.String()
	name := "user>>>" + inbound.User.Email + ">>>online"
	onlineMap, _ := stats.GetOrRegisterOnlineMap(s.statsManager, name)
	if onlineMap == nil {
		return func() {}
	}

	onlineMap.AddIP(userIP)
	return func() {
		onlineMap.RemoveIP(userIP)
	}
}

func hasTrustTunnelClientRandomRules(rules []*Rule) bool {
	for _, rule := range rules {
		if rule != nil && rule.GetClientRandom() != "" {
			return true
		}
	}
	return false
}

func (s *Server) serveHTTPConnectRequest(proto string, ctx context.Context, w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound, clientRandom string, cleanupConn stat.Connection) {
	if !strings.EqualFold(req.Method, http.MethodConnect) {
		writeH2Response(w, http.StatusMethodNotAllowed, "trusttunnel supports CONNECT only\n", nil)
		return
	}

	authHeader := req.Header.Get("Proxy-Authorization")
	user := s.users.GetByBasicAuth(authHeader)
	if user == nil {
		statusCode := int(s.config.GetAuthFailureStatusCode())
		if statusCode == 0 {
			statusCode = http.StatusProxyAuthRequired
		}

		headers := map[string]string{}
		if statusCode == http.StatusProxyAuthRequired {
			headers["Proxy-Authenticate"] = `Basic realm="trusttunnel"`
		}

		writeH2Response(w, statusCode, "authentication failed\n", headers)

		log.Record(&log.AccessMessage{
			From:   req.RemoteAddr,
			To:     req.Host,
			Status: log.AccessRejected,
			Reason: errors.New("trusttunnel authentication failed"),
		})
		return
	}

	if inboundTemplate != nil {
		inbound := *inboundTemplate
		inbound.User = user
		inbound.Name = "trusttunnel"
		inbound.CanSpliceCopy = 0
		ctx = session.ContextWithInbound(ctx, &inbound)
	}

	ctx = attachTrustTunnelClientRandom(ctx, clientRandom)
	if clientRandom != "" {
		errors.LogDebug(ctx, "trusttunnel client_random=", clientRandom)
	}

	allow, reason := isTrustTunnelAllowed(s.config.GetRules(), req.RemoteAddr, clientRandom)
	if reason != "" {
		errors.LogDebug(ctx, reason)
	}
	if !allow {
		writeH2Response(w, http.StatusForbidden, "connection rejected by rule\n", nil)
		log.Record(&log.AccessMessage{
			From:   req.RemoteAddr,
			To:     req.Host,
			Status: log.AccessRejected,
			Reason: errors.New(reason),
			Email:  user.Email,
		})
		return
	}

	if (proto == "H2" || proto == "H3") && isTrustTunnelHealthcheckHost(req.Host) {
		errors.LogInfo(ctx, "trusttunnel ", proto, " health-check accepted")
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		return
	}

	if s.serveMultipathControlRequest(proto, ctx, w, req, user, cleanupConn) {
		return
	}

	if isTrustTunnelUDPHost(req.Host) {
		if !s.config.GetEnableUdp() {
			writeH2Response(w, http.StatusForbidden, "udp is disabled\n", nil)
			return
		}

		releaseGuard, err := s.acquireRequestConnectionGuard(user, proto, cleanupConn)
		if err != nil {
			statusCode, body := trustTunnelConnectionRejection(err)
			writeH2Response(w, statusCode, body, nil)
			trustTunnelLogRejectedConnection(ctx, req.RemoteAddr, req.Host, user, err.Error())
			return
		}
		defer releaseGuard()
		s.serveUDPMuxRequest(proto, ctx, w, req, dispatcher)
		return
	}

	if isTrustTunnelICMPHost(req.Host) {
		releaseGuard, err := s.acquireRequestConnectionGuard(user, proto, cleanupConn)
		if err != nil {
			statusCode, body := trustTunnelConnectionRejection(err)
			writeH2Response(w, statusCode, body, nil)
			trustTunnelLogRejectedConnection(ctx, req.RemoteAddr, req.Host, user, err.Error())
			return
		}
		defer releaseGuard()
		s.serveICMPMuxRequest(proto, ctx, w, req)
		return
	}

	dest, err := http_proto.ParseHost(req.Host, net.Port(443))
	if err != nil {
		writeH2Response(w, http.StatusBadRequest, "invalid CONNECT host\n", nil)
		errors.LogWarningInner(ctx, err, "malformed trusttunnel "+strings.ToLower(proto)+" target")
		return
	}

	releaseGuard, err := s.acquireRequestConnectionGuard(user, proto, cleanupConn)
	if err != nil {
		statusCode, body := trustTunnelConnectionRejection(err)
		writeH2Response(w, statusCode, body, nil)
		trustTunnelLogRejectedConnection(ctx, req.RemoteAddr, req.Host, user, err.Error())
		return
	}
	defer releaseGuard()

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   req.RemoteAddr,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})

	errors.LogInfo(ctx, "trusttunnel ", proto, " CONNECT accepted for ", dest)

	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	if h3w, ok := w.(*countedH3ResponseWriter); ok {
		h3w.enableRawTunnelWrites()
	}

	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}

	writer := &flushWriter{
		w: w,
		f: flusher,
	}

	if err := s.dispatchConnectSession(ctx, dispatcher, dest, buf.NewReader(req.Body), buf.NewWriter(writer), req.Body); err != nil {
		errors.LogWarningInner(ctx, err, "failed to dispatch trusttunnel "+strings.ToLower(proto)+" CONNECT")
		if proto == "H2" {
			_ = forceCloseTrustTunnelConn(cleanupConn)
			panic(http.ErrAbortHandler)
		}
	}
}

func writeH2Response(w http.ResponseWriter, statusCode int, body string, headers map[string]string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	for k, v := range headers {
		if k != "" {
			h.Set(k, v)
		}
	}
	w.WriteHeader(statusCode)
	if body != "" {
		_, _ = io.WriteString(w, body)
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
}

func writePlainResponse(w io.Writer, statusCode int, statusText string, body string, headers map[string]string) {
	if statusText == "" {
		statusText = http.StatusText(statusCode)
	}
	if statusText == "" {
		statusText = "Status"
	}

	var b strings.Builder
	b.WriteString("HTTP/1.1 ")
	b.WriteString(strconv.Itoa(statusCode))
	b.WriteByte(' ')
	b.WriteString(statusText)
	b.WriteString("\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Length: ")
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteString("\r\n")
	for k, v := range headers {
		if k == "" {
			continue
		}
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)

	_, _ = io.WriteString(w, b.String())
}
