package signal

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type ActivityUpdater interface {
	Update()
}

type ActivityTimer struct {
	mu        sync.Mutex
	timer     *time.Timer
	timeout   time.Duration
	onTimeout func()
	consumed  atomic.Bool
	once      sync.Once
}

func (t *ActivityTimer) Update() {
	if t.consumed.Load() {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.consumed.Load() || t.timeout <= 0 {
		return
	}

	if t.timer != nil {
		t.timer.Stop()
	}
	t.timer = time.AfterFunc(t.timeout, t.finish)
}

func (t *ActivityTimer) finish() {
	t.once.Do(func() {
		t.consumed.Store(true)
		t.mu.Lock()
		if t.timer != nil {
			t.timer.Stop()
			t.timer = nil
		}
		t.mu.Unlock()
		t.onTimeout()
	})
}

func (t *ActivityTimer) SetTimeout(timeout time.Duration) {
	if t.consumed.Load() {
		return
	}
	if timeout == 0 {
		t.finish()
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.consumed.Load() {
		return
	}

	t.timeout = timeout
	if t.timer != nil {
		t.timer.Stop()
	}
	t.timer = time.AfterFunc(timeout, t.finish)
}

func CancelAfterInactivity(ctx context.Context, cancel context.CancelFunc, timeout time.Duration) *ActivityTimer {
	_ = ctx

	timer := &ActivityTimer{
		onTimeout: cancel,
	}
	timer.SetTimeout(timeout)
	return timer
}
