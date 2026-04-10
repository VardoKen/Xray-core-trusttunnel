package trusttunnel

import (
	"encoding/base64"
	"strings"
)

func ParseBasicAuthorization(header string) (username string, password string, ok bool) {
	if header == "" {
		return "", "", false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}

	enc := strings.TrimSpace(header[len(prefix):])
	if enc == "" {
		return "", "", false
	}

	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}
