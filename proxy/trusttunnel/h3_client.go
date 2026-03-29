package trusttunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/errors"
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
	transport *http3.Transport
	in        *io.PipeWriter
	out       io.ReadCloser
}

func (h *http3Conn) Read(p []byte) (int, error) {
	return h.out.Read(p)
}

func (h *http3Conn) Write(p []byte) (int, error) {
	return h.in.Write(p)
}

func (h *http3Conn) Close() error {
	_ = h.in.Close()
	_ = h.out.Close()
	if h.transport != nil {
		_ = h.transport.Close()
	}
	return nil
}

func connectHTTP3(ctx context.Context, serverAddr string, targetHost string, account *MemoryAccount, cfg *ClientConfig) (io.ReadWriteCloser, error) {
	req, err := buildHTTP3ConnectRequest(serverAddr, targetHost, account)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	req.Body = pr
	req = req.WithContext(ctx)

	tlsCfg := &tls.Config{
		ServerName:         cfg.GetHostname(),
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyTrustTunnelTLS(cs.PeerCertificates, cfg)
		},
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      &quic.Config{},
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = transport.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		_ = transport.Close()
		return nil, errors.New("trusttunnel CONNECT failed with status ", resp.StatusCode, ": ", string(body))
	}

	return &http3Conn{
		transport: transport,
		in:        pw,
		out:       resp.Body,
	}, nil
}
