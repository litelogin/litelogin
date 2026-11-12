package email

import (
	"context"
	"errors"
	"testing"

	"github.com/litelogin/litelogin/internal/metrics"
)

type failing struct{ err error }

func (f failing) Send(context.Context, Message) error { return f.err }

func TestMetered(t *testing.T) {
	m := &metrics.Memory{}
	_ = Metered(failing{}, m).Send(context.Background(), Message{})
	if err := Metered(failing{errors.New("SES down")}, m).Send(context.Background(), Message{}); err == nil {
		t.Fatal("error swallowed")
	}
	if m.Sum(metrics.EmailFailed) != 1 {
		t.Errorf("records = %+v", m.Records)
	}
}
