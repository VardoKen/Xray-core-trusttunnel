package trusttunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"reflect"
	"unsafe"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/errors"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
)

func buildHTTP3ConnectRequest(serverAddr string, targetHost string, account *MemoryAccount) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodConnect, "https://"+serverAddr, nil)
	if err != nil {
		return nil, err
	}

	req.Host = targetHost
	req.Header.Set("Host", targetHost)
	req.Header.Set("Proxy-Authorization", buildBasicAuthValue(account.Username, account.Password))
	req.Header.Set("User-Agent", "trusttunnel-xray-mvp/1")

	return req, nil
}

type http3Conn struct {
	conn   *quic.Conn
	stream *http3.Stream
}

func (h *http3Conn) Read(p []byte) (int, error) {
	return h.stream.Read(p)
}

func (h *http3Conn) Write(p []byte) (int, error) {
	return h.stream.Write(p)
}

func (h *http3Conn) Close() error {
	if h.stream != nil {
		h.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		h.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = h.stream.Close()
	}
	if h.conn != nil {
		return h.conn.CloseWithError(0, "")
	}
	return nil
}

// quic-go's client-side CONNECT path currently exposes only RequestStream after
// ReadResponse(), and that wrapper forces successful CONNECT responses into a
// zero-length response-body model. TrustTunnel needs the raw HTTP/3 stream for
// tunnel semantics, so we extract the underlying *http3.Stream until quic-go
// exposes an official client-side hijack API for CONNECT.
func trustTunnelExtractHTTP3TunnelStream(reqStream *http3.RequestStream) (*http3.Stream, error) {
	if reqStream == nil {
		return nil, errors.New("trusttunnel HTTP/3 request stream is missing")
	}

	value := reflect.ValueOf(reqStream)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, errors.New("trusttunnel HTTP/3 request stream is invalid")
	}

	field := value.Elem().FieldByName("str")
	if !field.IsValid() || field.IsNil() {
		return nil, errors.New("trusttunnel HTTP/3 raw stream is unavailable")
	}
	if !field.CanAddr() {
		return nil, errors.New("trusttunnel HTTP/3 raw stream is not addressable")
	}

	raw := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
	stream, ok := raw.(*http3.Stream)
	if !ok || stream == nil {
		return nil, errors.New("trusttunnel HTTP/3 raw stream has unexpected type")
	}

	return stream, nil
}

func connectHTTP3(ctx context.Context, serverAddr string, targetHost string, account *MemoryAccount, cfg *ClientConfig) (io.ReadWriteCloser, error) {
	req, err := buildHTTP3ConnectRequest(serverAddr, targetHost, account)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	tlsCfg := &tls.Config{
		ServerName:         cfg.GetHostname(),
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyTrustTunnelTLS(cs.PeerCertificates, cfg)
		},
	}
	trustTunnelApplyHTTP3PostQuantum(tlsCfg, cfg)
	if spec := cfg.GetClientRandom(); spec != "" {
		reader, err := xtlstls.NewClientHelloRandomReader(spec, tlsCfg.Rand)
		if err != nil {
			return nil, errors.New("failed to apply trusttunnel HTTP/3 clientRandom").Base(err)
		}
		tlsCfg.Rand = reader
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      &quic.Config{},
	}
	conn, err := quic.DialAddr(ctx, serverAddr, tlsCfg, transport.QUICConfig)
	if err != nil {
		return nil, err
	}
	clientConn := transport.NewClientConn(conn)
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	if err := stream.SendRequestHeader(req); err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = conn.CloseWithError(0, "")
		return nil, err
	}

	resp, err := stream.ReadResponse()
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = conn.CloseWithError(0, "")
		return nil, errors.New("trusttunnel CONNECT failed with status ", resp.StatusCode, ": ", string(body))
	}
	rawStream, err := trustTunnelExtractHTTP3TunnelStream(stream)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}

	return &http3Conn{
		conn:   conn,
		stream: rawStream,
	}, nil
}
