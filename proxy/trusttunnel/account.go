package trusttunnel

import (
	"crypto/subtle"
	"encoding/base64"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

type MemoryAccount struct {
	Username  string
	Password  string
	BasicAuth string
}

func (a *Account) AsAccount() (protocol.Account, error) {
	ma := &MemoryAccount{
		Username: a.GetUsername(),
		Password: a.GetPassword(),
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
		Username: a.Username,
		Password: a.Password,
	}
}

func buildBasicAuthValue(username, password string) string {
	raw := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}
