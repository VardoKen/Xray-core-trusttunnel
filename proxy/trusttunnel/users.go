package trusttunnel

import (
	"crypto/subtle"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

type UserStore struct {
	email    sync.Map
	username sync.Map
}

func normalizeEmail(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeUsername(v string) string {
	return strings.TrimSpace(v)
}

func (s *UserStore) Add(u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("trusttunnel user is nil")
	}

	acc, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("trusttunnel user account is not valid")
	}

	usernameKey := normalizeUsername(acc.Username)
	if usernameKey == "" {
		return errors.New("trusttunnel username must not be empty")
	}
	if acc.Password == "" {
		return errors.New("trusttunnel password must not be empty")
	}

	acc.BasicAuth = buildBasicAuthValue(acc.Username, acc.Password)

	if u.Email != "" {
		emailKey := normalizeEmail(u.Email)
		_, loaded := s.email.LoadOrStore(emailKey, u)
		if loaded {
			return errors.New("trusttunnel email already exists: ", u.Email)
		}
	}

	_, loaded := s.username.LoadOrStore(usernameKey, u)
	if loaded {
		if u.Email != "" {
			s.email.Delete(normalizeEmail(u.Email))
		}
		return errors.New("trusttunnel username already exists: ", acc.Username)
	}

	return nil
}

func (s *UserStore) Del(email string) error {
	emailKey := normalizeEmail(email)
	if emailKey == "" {
		return errors.New("email must not be empty")
	}

	u, ok := s.email.Load(emailKey)
	if !ok || u == nil {
		return errors.New("user not found: ", email)
	}

	s.email.Delete(emailKey)

	acc, ok := u.(*protocol.MemoryUser).Account.(*MemoryAccount)
	if ok {
		s.username.Delete(normalizeUsername(acc.Username))
	}

	return nil
}

func (s *UserStore) GetByEmail(email string) *protocol.MemoryUser {
	u, _ := s.email.Load(normalizeEmail(email))
	if u == nil {
		return nil
	}
	return u.(*protocol.MemoryUser)
}

func (s *UserStore) GetByUsername(username string) *protocol.MemoryUser {
	u, _ := s.username.Load(normalizeUsername(username))
	if u == nil {
		return nil
	}
	return u.(*protocol.MemoryUser)
}

func (s *UserStore) GetByBasicAuth(header string) *protocol.MemoryUser {
	var matched *protocol.MemoryUser

	s.username.Range(func(_, value interface{}) bool {
		u := value.(*protocol.MemoryUser)
		acc, ok := u.Account.(*MemoryAccount)
		if !ok {
			return true
		}

		if subtle.ConstantTimeCompare([]byte(acc.BasicAuth), []byte(header)) == 1 {
			matched = u
			return false
		}

		return true
	})

	return matched
}

func (s *UserStore) GetAll() []*protocol.MemoryUser {
	users := make([]*protocol.MemoryUser, 0, 32)
	s.username.Range(func(_, value interface{}) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return users
}

func (s *UserStore) GetCount() int64 {
	var count int64
	s.username.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
