package trusttunnel

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/net/http2"
)

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Server struct {
	config *ServerConfig
	users  *UserStore
}

type bufferedConn struct {
	stat.Connection
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
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

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	_ = ctx

	store := &UserStore{}

	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get trusttunnel user").Base(err).AtError()
		}
		if err := store.Add(u); err != nil {
			return nil, errors.New("failed to add trusttunnel user").Base(err).AtError()
		}
	}

	return &Server{
		config: config,
		users:  store,
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

func isTimeout(err error) bool {
	nerr, ok := errors.Cause(err).(net.Error)
	return ok && nerr.Timeout()
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "trusttunnel"
		inbound.CanSpliceCopy = 2
	}

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		errors.LogInfoInner(ctx, err, "failed to set read deadline")
	}

	reader := bufio.NewReaderSize(conn, 64*1024)

	preface, err := reader.Peek(len(h2ClientPreface))
	if err == nil && bytes.Equal(preface, []byte(h2ClientPreface)) {
		if _, err := reader.Discard(len(h2ClientPreface)); err != nil {
			return errors.New("failed to discard http2 preface").Base(err).AtWarning()
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			errors.LogDebugInner(ctx, err, "failed to clear read deadline")
		}
		return s.processHTTP2(ctx, &bufferedConn{Connection: conn, reader: reader}, dispatcher, inbound)
	}

	return s.processHTTP1(ctx, conn, reader, dispatcher, inbound)
}

func (s *Server) processHTTP1(ctx context.Context, conn stat.Connection, reader *bufio.Reader, dispatcher routing.Dispatcher, inbound *session.Inbound) error {
Start:
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

	dest, err := http_proto.ParseHost(req.Host, net.Port(443))
	if err != nil {
		writePlainResponse(conn, http.StatusBadRequest, "Bad Request", "invalid CONNECT host\n", map[string]string{
			"Connection": "close",
		})
		return errors.New("malformed trusttunnel target: ", req.Host).Base(err).AtWarning()
	}

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

	if err := dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: linkReader,
		Writer: buf.NewWriter(conn),
	}); err != nil {
		return errors.New("failed to dispatch trusttunnel CONNECT").Base(err).AtWarning()
	}

	if strings.EqualFold(req.Header.Get("Proxy-Connection"), "keep-alive") {
		goto Start
	}

	return nil
}

func (s *Server) processHTTP2(ctx context.Context, conn *bufferedConn, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound) error {
	done := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.serveHTTP2Request(w, req, dispatcher, inboundTemplate)
	})

	go func() {
		defer close(done)
		var h2s http2.Server
		h2s.ServeConn(conn, &http2.ServeConnOpts{
			Context:          ctx,
			Handler:          handler,
			SawClientPreface: true,
		})
	}()

	<-done
	return nil
}

func (s *Server) serveHTTP2Request(w http.ResponseWriter, req *http.Request, dispatcher routing.Dispatcher, inboundTemplate *session.Inbound) {
	ctx := req.Context()

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

	dest, err := http_proto.ParseHost(req.Host, net.Port(443))
	if err != nil {
		writeH2Response(w, http.StatusBadRequest, "invalid CONNECT host\n", nil)
		errors.LogWarningInner(ctx, err, "malformed trusttunnel h2 target")
		return
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   req.RemoteAddr,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})

	errors.LogInfo(ctx, "trusttunnel H2 CONNECT accepted for ", dest)

	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}

	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}

	writer := &flushWriter{
		w: w,
		f: flusher,
	}

	if err := dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: buf.NewReader(req.Body),
		Writer: buf.NewWriter(writer),
	}); err != nil {
		errors.LogWarningInner(ctx, err, "failed to dispatch trusttunnel h2 CONNECT")
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
