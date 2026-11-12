package email

import (
	"context"

	"github.com/litelogin/litelogin/internal/metrics"
)

// Metered counts failed sends around a Sender. A nil
// recorder returns s.
func Metered(s Sender, r metrics.Recorder) Sender {
	if r == nil || s == nil {
		return s
	}
	return &metered{s: s, r: r}
}

type metered struct {
	s Sender
	r metrics.Recorder
}

func (m *metered) Send(ctx context.Context, msg Message) error {
	err := m.s.Send(ctx, msg)
	if err != nil {
		metrics.Count(m.r, metrics.EmailFailed, 1)
	}
	return err
}
