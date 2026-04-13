package trusttunnel

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/routing"
)

func (s *Server) startMultipathAttachDeadlineWatcher(ctx context.Context, sessionState *trustTunnelMultipathSession) {
	if s == nil || sessionState == nil {
		return
	}

	go func() {
		wait := time.Until(sessionState.attachDeadline)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()

		select {
		case <-sessionState.Closed():
			return
		case <-timer.C:
		}

		select {
		case <-sessionState.Ready():
			return
		default:
		}

		err := errors.New("trusttunnel multipath attach quorum was not reached before attach deadline").AtInfo()
		errors.LogInfo(ctx, err)
		sessionState.Close(err)
		s.multipathSessions.Delete(sessionState.ID())
	}()
}

func (s *Server) maybeStartMultipathServerSession(ctx context.Context, sessionState *trustTunnelMultipathSession, dispatcher routing.Dispatcher) {
	if s == nil || sessionState == nil || dispatcher == nil {
		return
	}
	if sessionState.ActiveChannelCount() < int(sessionState.minChannels) {
		return
	}

	sessionState.startOnce.Do(func() {
		sessionCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		go func() {
			select {
			case <-sessionState.Closed():
				cancel()
			case <-sessionCtx.Done():
			}
		}()
		go func() {
			defer cancel()
			s.runMultipathServerSession(sessionCtx, sessionState, dispatcher)
		}()
	})
}

func (s *Server) runMultipathServerSession(ctx context.Context, sessionState *trustTunnelMultipathSession, dispatcher routing.Dispatcher) {
	defer s.multipathSessions.Delete(sessionState.ID())

	stream, err := newTrustTunnelMultipathStream(sessionState)
	if err != nil {
		errors.LogWarningInner(ctx, err, "trusttunnel multipath server session failed before stream startup session=", sessionState.ID())
		sessionState.Close(err)
		return
	}
	defer stream.Close()

	if err := s.dispatchConnectSession(ctx, dispatcher, sessionState.target, buf.NewReader(stream), buf.NewWriter(stream), stream); err != nil {
		errors.LogWarningInner(ctx, err, "trusttunnel multipath server session dispatch ended session=", sessionState.ID())
		sessionState.Close(err)
		return
	}

	errors.LogInfo(ctx, "trusttunnel multipath server session completed session=", sessionState.ID())
	sessionState.Close(nil)
}

func (s *Server) waitForMultipathSession(ctx context.Context, sessionState *trustTunnelMultipathSession) {
	if sessionState == nil {
		return
	}

	<-sessionState.Closed()
}
