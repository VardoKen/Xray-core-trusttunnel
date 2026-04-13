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

		if sessionState.State() == trustTunnelMultipathSessionActive {
			return
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
		go s.runMultipathServerSession(ctx, sessionState, dispatcher)
	})
}

func (s *Server) runMultipathServerSession(ctx context.Context, sessionState *trustTunnelMultipathSession, dispatcher routing.Dispatcher) {
	defer s.multipathSessions.Delete(sessionState.ID())

	stream, err := newTrustTunnelMultipathStream(sessionState)
	if err != nil {
		sessionState.Close(err)
		return
	}
	defer stream.Close()

	if err := s.dispatchConnectSession(ctx, dispatcher, sessionState.target, buf.NewReader(stream), buf.NewWriter(stream), stream); err != nil {
		sessionState.Close(err)
		return
	}

	sessionState.Close(nil)
}

func (s *Server) waitForMultipathSession(ctx context.Context, sessionState *trustTunnelMultipathSession) {
	if sessionState == nil {
		return
	}

	select {
	case <-ctx.Done():
		sessionState.Close(ctx.Err())
	case <-sessionState.Closed():
	}
}
