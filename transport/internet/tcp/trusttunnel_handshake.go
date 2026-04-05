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

	abortTimer := time.AfterFunc(timeout, func() {
		_ = forceCloseTrustTunnelConn(conn)
	})
	defer abortTimer.Stop()

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

func forceCloseTrustTunnelConn(conn gonet.Conn) error {
	if conn == nil {
		return nil
	}

	if rawConn, ok := conn.(interface{ NetConn() gonet.Conn }); ok {
		return rawConn.NetConn().Close()
	}

	return conn.Close()
}
