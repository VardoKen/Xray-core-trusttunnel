package internet

import (
	"context"
	"testing"
)

func TestStreamSettingsFromContextUsesOverride(t *testing.T) {
	fallback := &MemoryStreamConfig{ProtocolName: "tcp"}
	override := &MemoryStreamConfig{ProtocolName: "splithttp"}

	ctx := ContextWithStreamSettingsOverride(context.Background(), override)
	if got := StreamSettingsFromContext(ctx, fallback); got != override {
		t.Fatalf("StreamSettingsFromContext() = %p, want override %p", got, override)
	}
}

func TestStreamSettingsFromContextFallsBack(t *testing.T) {
	fallback := &MemoryStreamConfig{ProtocolName: "tcp"}

	if got := StreamSettingsFromContext(context.Background(), fallback); got != fallback {
		t.Fatalf("StreamSettingsFromContext() = %p, want fallback %p", got, fallback)
	}
}
