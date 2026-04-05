package tcp

import (
	"context"
	gonet "net"
	"time"

	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
)

func trustTunnelServerHandshake(conn gonet.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}

	handshakeConn, ok := conn.(xtlstls.Interface)
	if !ok {
		return nil
	}

	deadlineSet := false
	if err := conn.SetDeadline(time.Now().Add(timeout)); err == nil {
		deadlineSet = true
	}
	if deadlineSet {
		defer conn.SetDeadline(time.Time{})
	}

	handshakeCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return handshakeConn.HandshakeContext(handshakeCtx)
}
