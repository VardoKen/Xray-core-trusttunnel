package trusttunnel

import (
	"crypto/subtle"
	"encoding/base64"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

type MemoryAccount struct {
	Username      string
	Password      string
	BasicAuth     string
	MaxHTTP2Conns uint32
	MaxHTTP3Conns uint32
}

func (a *Account) AsAccount() (protocol.Account, error) {
	ma := &MemoryAccount{
		Username:      a.GetUsername(),
		Password:      a.GetPassword(),
		MaxHTTP2Conns: a.GetMaxHttp2Conns(),
		MaxHTTP3Conns: a.GetMaxHttp3Conns(),
	}
	ma.BasicAuth = buildBasicAuthValue(ma.Username, ma.Password)
	return ma, nil
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	other, ok := another.(*MemoryAccount)
	if !ok {
		return false
	}

	if subtle.ConstantTimeCompare([]byte(a.Username), []byte(other.Username)) != 1 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(a.Password), []byte(other.Password)) == 1
}

func (a *MemoryAccount) ToProto() proto.Message {
	if a == nil {
		return (*Account)(nil)
	}

	return &Account{
		Username:      a.Username,
		Password:      a.Password,
		MaxHttp2Conns: a.MaxHTTP2Conns,
		MaxHttp3Conns: a.MaxHTTP3Conns,
	}
}

func buildBasicAuthValue(username, password string) string {
	raw := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}
