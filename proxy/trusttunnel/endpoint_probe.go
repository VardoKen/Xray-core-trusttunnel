package trusttunnel

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
)

const trustTunnelHealthcheckPseudoHost = "_check:443"

var (
	trustTunnelEndpointActiveProbeInterval = 1 * time.Second
	trustTunnelEndpointActiveProbeTimeout  = 3 * time.Second
)

type trustTunnelEndpointProbeFunc func(context.Context, trustTunnelServerAttempt) error

func (c *Client) maybeStartCoolingEndpointProbes(
	ctx context.Context,
	attempts []trustTunnelServerAttempt,
	attemptLabel string,
	probe trustTunnelEndpointProbeFunc,
) {
	if probe == nil || len(attempts) < 2 || trustTunnelEndpointActiveProbeInterval <= 0 {
		return
	}

	baseCtx := context.WithoutCancel(ctx)
	now := time.Now()
	total := len(c.serverSpecs())
	for _, attempt := range attempts {
		if !c.serverInFailureCooldown(attempt.index, now) {
			continue
		}
		c.startActiveProbe(baseCtx, attempt, total, attemptLabel, probe)
	}
}

func (c *Client) startActiveProbe(
	ctx context.Context,
	attempt trustTunnelServerAttempt,
	totalAttempts int,
	attemptLabel string,
	probe trustTunnelEndpointProbeFunc,
) {
	if _, loaded := c.serverProbeInFlight.LoadOrStore(attempt.index, struct{}{}); loaded {
		return
	}

	go func() {
		defer c.serverProbeInFlight.Delete(attempt.index)

		timer := time.NewTimer(trustTunnelEndpointActiveProbeInterval)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}

			now := time.Now()
			if !c.serverInFailureCooldown(attempt.index, now) {
				return
			}

			probeTimeout := trustTunnelEndpointActiveProbeTimeout
			if probeTimeout <= 0 {
				probeTimeout = trustTunnelEndpointActiveProbeInterval
			}
			probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeTimeout)
			start := time.Now()
			err := probe(probeCtx, attempt)
			cancel()
			if err == nil {
				c.noteServerSuccess(attempt.index)
				errors.LogInfo(ctx, "trusttunnel active probe restored ", attemptLabel, " ", attempt.index+1, "/", totalAttempts, " in ", time.Since(start))
				return
			}

			errors.LogDebugInner(ctx, err, "trusttunnel active probe failed for ", attemptLabel, " ", attempt.index+1, "/", totalAttempts)

			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(trustTunnelEndpointActiveProbeInterval)
		}
	}()
}

func (c *Client) probeStreamEndpointHealth(
	ctx context.Context,
	dialer internet.Dialer,
	server *protocol.ServerSpec,
	account *MemoryAccount,
	tlsHandledByStreamSettings bool,
) error {
	tunnelConn, err := c.connectStreamTunnel(ctx, dialer, server, account, trustTunnelHealthcheckPseudoHost, tlsHandledByStreamSettings)
	if err != nil {
		return err
	}
	return tunnelConn.Close()
}
