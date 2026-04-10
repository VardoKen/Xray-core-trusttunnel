package internet

import "context"

type streamSettingsOverrideKey struct{}

// ContextWithStreamSettingsOverride attaches an effective per-request stream settings
// overlay to the context. The override is consumed by outbound dial paths that
// normally rely on handler-level stream settings.
func ContextWithStreamSettingsOverride(ctx context.Context, streamSettings *MemoryStreamConfig) context.Context {
	if streamSettings == nil {
		return ctx
	}
	return context.WithValue(ctx, streamSettingsOverrideKey{}, streamSettings)
}

func StreamSettingsOverrideFromContext(ctx context.Context) *MemoryStreamConfig {
	if ctx == nil {
		return nil
	}
	if streamSettings, ok := ctx.Value(streamSettingsOverrideKey{}).(*MemoryStreamConfig); ok {
		return streamSettings
	}
	return nil
}

func StreamSettingsFromContext(ctx context.Context, fallback *MemoryStreamConfig) *MemoryStreamConfig {
	if override := StreamSettingsOverrideFromContext(ctx); override != nil {
		return override
	}
	return fallback
}
