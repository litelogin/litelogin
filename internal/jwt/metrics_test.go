package jwt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"

	"github.com/litelogin/litelogin/internal/metrics"
)

type stubKMS struct{ err error }

func (s stubKMS) Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
	return &kms.SignOutput{}, s.err
}

func TestMeteredKMS(t *testing.T) {
	m := &metrics.Memory{}
	ctx := context.Background()
	for _, err := range []error{nil, &smithy.GenericAPIError{Code: "ThrottlingException"}, errors.New("boom")} {
		_, _ = MeteredKMS(stubKMS{err}, m).Sign(ctx, &kms.SignInput{})
	}
	if m.Sum(metrics.KMSSignFailed, metrics.Reason("throttled")) != 1 || m.Sum(metrics.KMSSignFailed, metrics.Reason("error")) != 1 ||
		len(m.Records) != 5 || !m.Has(metrics.KMSSignLatency) {
		t.Errorf("records = %+v", m.Records)
	}
	if k := (stubKMS{}); MeteredKMS(k, nil) != k {
		t.Error("a nil recorder wrapped the signer")
	}
}
