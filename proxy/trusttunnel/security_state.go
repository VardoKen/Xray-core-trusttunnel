package trusttunnel

import (
	"context"
	"crypto/x509"
	"reflect"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtlstls "github.com/xtls/xray-core/transport/internet/tls"
)

type trustTunnelSecurityState struct {
	NegotiatedProtocol string
	PeerCertificates   []*x509.Certificate
	UsesReality        bool
}

var trustTunnelPeerCertificatesType = reflect.TypeOf([]*x509.Certificate(nil))

func trustTunnelClientSecurityState(ctx context.Context, conn stat.Connection) (trustTunnelSecurityState, error) {
	var zero trustTunnelSecurityState

	if conn == nil {
		return zero, nil
	}

	inner := stat.TryUnwrapStatsConn(conn)
	if handshaker, ok := inner.(interface{ HandshakeContext(context.Context) error }); ok {
		if err := handshaker.HandshakeContext(ctx); err != nil {
			return zero, errors.New(trustTunnelHandshakeFailureLabel(inner)).Base(err).AtWarning()
		}
	}

	state := trustTunnelExtractSecurityState(inner)
	state.UsesReality = trustTunnelIsRealityConn(inner)
	return state, nil
}

func trustTunnelHandshakeFailureLabel(conn any) string {
	switch conn.(type) {
	case *xtlstls.Conn:
		return "failed TLS handshake"
	case *xtlstls.UConn:
		return "failed uTLS handshake"
	case *reality.Conn, *reality.UConn:
		return "failed REALITY handshake"
	default:
		return "failed security handshake"
	}
}

func trustTunnelIsRealityConn(conn any) bool {
	switch conn.(type) {
	case *reality.Conn, *reality.UConn:
		return true
	default:
		return false
	}
}

func trustTunnelNegotiatedProtocol(conn stat.Connection) string {
	if conn == nil {
		return ""
	}

	if proto := trustTunnelNegotiatedProtocolFromAny(conn); proto != "" {
		return proto
	}

	return trustTunnelNegotiatedProtocolFromAny(stat.TryUnwrapStatsConn(conn))
}

func trustTunnelNegotiatedProtocolFromAny(conn any) string {
	if conn == nil {
		return ""
	}

	if negotiated, ok := conn.(interface{ NegotiatedProtocol() string }); ok {
		return negotiated.NegotiatedProtocol()
	}

	return trustTunnelExtractSecurityState(conn).NegotiatedProtocol
}

func trustTunnelExtractSecurityState(conn any) trustTunnelSecurityState {
	var state trustTunnelSecurityState

	if conn == nil {
		return state
	}

	method := reflect.ValueOf(conn).MethodByName("ConnectionState")
	if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 1 {
		return state
	}

	result := method.Call(nil)
	if len(result) != 1 {
		return state
	}

	value := result[0]
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return state
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return state
	}

	if field := value.FieldByName("NegotiatedProtocol"); field.IsValid() && field.Kind() == reflect.String {
		state.NegotiatedProtocol = field.String()
	}

	if field := value.FieldByName("PeerCertificates"); field.IsValid() && field.Type() == trustTunnelPeerCertificatesType {
		state.PeerCertificates = field.Interface().([]*x509.Certificate)
	}

	return state
}

func trustTunnelShouldUseHTTP2(state trustTunnelSecurityState) bool {
	if state.NegotiatedProtocol == "h2" {
		return true
	}

	// REALITY may intentionally complete without exposing ALPN to the wrapped
	// application layer, but the transport can still carry a valid HTTP/2 preface.
	return state.UsesReality && state.NegotiatedProtocol == ""
}
