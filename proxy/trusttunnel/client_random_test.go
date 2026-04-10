package trusttunnel

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/session"
)

func TestAttachTrustTunnelClientRandomClonesSharedContent(t *testing.T) {
	baseContent := &session.Content{
		Protocol: "http",
		Attributes: map[string]string{
			"base": "value",
		},
	}

	parentCtx := session.ContextWithContent(context.Background(), baseContent)

	ctxOne := attachTrustTunnelClientRandom(parentCtx, "aa")
	ctxTwo := attachTrustTunnelClientRandom(parentCtx, "bb")

	if got := baseContent.Attribute("trusttunnel.client_random"); got != "" {
		t.Fatalf("base content was mutated: got %q", got)
	}

	contentOne := session.ContentFromContext(ctxOne)
	contentTwo := session.ContentFromContext(ctxTwo)
	if contentOne == nil || contentTwo == nil {
		t.Fatal("attached content is nil")
	}
	if contentOne == baseContent || contentTwo == baseContent {
		t.Fatal("attached context reused the shared content pointer")
	}
	if got := contentOne.Attribute("base"); got != "value" {
		t.Fatalf("contentOne lost base attribute: got %q", got)
	}
	if got := contentTwo.Attribute("base"); got != "value" {
		t.Fatalf("contentTwo lost base attribute: got %q", got)
	}
	if got := contentOne.Attribute("trusttunnel.client_random"); got != "aa" {
		t.Fatalf("contentOne client_random = %q, want %q", got, "aa")
	}
	if got := contentTwo.Attribute("trusttunnel.client_random"); got != "bb" {
		t.Fatalf("contentTwo client_random = %q, want %q", got, "bb")
	}

	contentOne.SetAttribute("probe", "one")
	if got := contentTwo.Attribute("probe"); got != "" {
		t.Fatalf("contentTwo observed mutation from contentOne: got %q", got)
	}
	if got := baseContent.Attribute("probe"); got != "" {
		t.Fatalf("base content observed mutation from clone: got %q", got)
	}
}
