package trusttunnel

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

var trustTunnelEndpointRaceDelay = 1 * time.Second

type trustTunnelEndpointConnectFunc func(context.Context, trustTunnelServerAttempt) (io.ReadWriteCloser, error)

type trustTunnelEndpointConnectResult struct {
	attempt   trustTunnelServerAttempt
	conn      io.ReadWriteCloser
	err       error
	cancelled bool
}

func (c *Client) connectWithEndpointPolicy(
	ctx context.Context,
	attempts []trustTunnelServerAttempt,
	attemptLabel string,
	connect trustTunnelEndpointConnectFunc,
) (io.ReadWriteCloser, error) {
	if len(attempts) == 0 {
		return nil, errors.New("no target trusttunnel server found")
	}

	var (
		lastErr error
		start   int
	)

	now := time.Now()
	if c.shouldRaceEndpointAttempts(attempts, now) {
		tunnelConn, err := c.connectWithDelayedEndpointRace(ctx, attempts[0], attempts[1], len(attempts), attemptLabel, connect)
		if err == nil {
			return tunnelConn, nil
		}
		lastErr = err
		start = 2
	}

	for idx := start; idx < len(attempts); idx++ {
		attempt := attempts[idx]
		tunnelConn, err := connect(ctx, attempt)
		if err != nil {
			c.noteServerFailure(attempt.index)
			lastErr = err
			if idx+1 < len(attempts) {
				errors.LogWarning(ctx, "trusttunnel server ", idx+1, "/", len(attempts), " failed; trying next ", attemptLabel, ": ", err)
				continue
			}
			break
		}

		c.noteServerSuccess(attempt.index)
		return tunnelConn, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no target trusttunnel server found")
}

func (c *Client) shouldRaceEndpointAttempts(attempts []trustTunnelServerAttempt, now time.Time) bool {
	if len(attempts) < 2 {
		return false
	}
	if trustTunnelEndpointRaceDelay <= 0 {
		return false
	}
	if c.serverInFailureCooldown(attempts[0].index, now) {
		return false
	}
	if c.serverInFailureCooldown(attempts[1].index, now) {
		return false
	}
	return true
}

func (c *Client) connectWithDelayedEndpointRace(
	ctx context.Context,
	primary trustTunnelServerAttempt,
	secondary trustTunnelServerAttempt,
	totalAttempts int,
	attemptLabel string,
	connect trustTunnelEndpointConnectFunc,
) (io.ReadWriteCloser, error) {
	resultCh := make(chan trustTunnelEndpointConnectResult, 2)

	primaryCtx, cancelPrimary := context.WithCancel(ctx)
	defer cancelPrimary()
	secondaryCtx, cancelSecondary := context.WithCancel(ctx)
	defer cancelSecondary()

	startAttempt := func(runCtx context.Context, attempt trustTunnelServerAttempt) {
		go func() {
			conn, err := connect(runCtx, attempt)
			cancelled := runCtx.Err() != nil && ctx.Err() == nil
			if cancelled && conn != nil {
				_ = conn.Close()
				conn = nil
			}
			resultCh <- trustTunnelEndpointConnectResult{
				attempt:   attempt,
				conn:      conn,
				err:       err,
				cancelled: cancelled,
			}
		}()
	}

	startAttempt(primaryCtx, primary)
	inFlight := 1
	secondaryStarted := false
	timer := time.NewTimer(trustTunnelEndpointRaceDelay)
	defer timer.Stop()

	var lastErr error
	for inFlight > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			if secondaryStarted {
				continue
			}
			secondaryStarted = true
			inFlight++
			errors.LogInfo(ctx, "trusttunnel delayed endpoint race started next ", attemptLabel, " after ", trustTunnelEndpointRaceDelay)
			startAttempt(secondaryCtx, secondary)
		case result := <-resultCh:
			inFlight--
			if result.cancelled {
				continue
			}
			if result.err == nil {
				c.noteServerSuccess(result.attempt.index)
				if result.attempt.index == primary.index {
					cancelSecondary()
				} else {
					cancelPrimary()
				}
				return result.conn, nil
			}

			c.noteServerFailure(result.attempt.index)
			lastErr = result.err

			if result.attempt.index == primary.index && !secondaryStarted {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				secondaryStarted = true
				inFlight++
				errors.LogWarning(ctx, "trusttunnel server 1/", totalAttempts, " failed before delayed race timeout; trying next ", attemptLabel, " immediately: ", result.err)
				startAttempt(secondaryCtx, secondary)
				continue
			}
		}
	}

	return nil, lastErr
}
