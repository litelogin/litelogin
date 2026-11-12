package jwt

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"

	"github.com/litelogin/litelogin/internal/metrics"
)

// MeteredKMS records KMS Sign latency, and its failures by reason
// (throttled or error), around a KMSSigner. A nil recorder returns k.
func MeteredKMS(k KMSSigner, r metrics.Recorder) KMSSigner {
	if r == nil {
		return k
	}
	return &meteredKMS{k: k, r: r}
}

type meteredKMS struct {
	k KMSSigner
	r metrics.Recorder
}

func (m *meteredKMS) Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	start := time.Now()
	out, err := m.k.Sign(ctx, in, opts...)
	metrics.Since(m.r, metrics.KMSSignLatency, start)
	if err != nil {
		reason := "error"
		if throttled(err) {
			reason = "throttled"
		}
		metrics.Count(m.r, metrics.KMSSignFailed, 1, metrics.Reason(reason))
	}
	return out, err
}

// throttled reports whether err is KMS throttling (a request rate quota
// exceeded), which the SDK returns once its retries are spent.
func throttled(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "ThrottlingException", "LimitExceededException", "RequestLimitExceeded", "TooManyRequestsException":
		return true
	}
	return false
}
