// Package kmsfake is an in-memory stand-in for the parts of AWS KMS that
// LiteLogin uses (asymmetric RSA signing keys), for tests.
package kmsfake

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Key is one fake KMS key.
type Key struct {
	ARN             string
	Private         *rsa.PrivateKey
	Tags            map[string]string
	PendingDeletion bool
	DeletionDays    int32
}

// KMS is a fake KMS. The zero value is not usable; call New.
type KMS struct {
	mu   sync.Mutex
	keys map[string]*Key
	next int

	// FailCreate, FailSign and FailSchedule make the next call fail.
	FailCreate, FailSign, FailSchedule error
	// SignCalls counts Sign calls.
	SignCalls int
}

// New returns an empty fake KMS.
func New() *KMS { return &KMS{keys: map[string]*Key{}} }

// Keys returns a snapshot of every key, including those pending deletion.
func (f *KMS) Keys() []Key {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Key, 0, len(f.keys))
	for _, k := range f.keys {
		out = append(out, *k)
	}
	return out
}

// CreateKey creates an RSA_2048 SIGN_VERIFY key.
func (f *KMS) CreateKey(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.FailCreate; err != nil {
		f.FailCreate = nil
		return nil, err
	}
	if in.KeySpec != types.KeySpecRsa2048 || in.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kmsfake: only RSA_2048 SIGN_VERIFY keys are supported")
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f.next++
	arn := fmt.Sprintf("arn:aws:kms:us-east-1:111111111111:key/fake-%d", f.next)
	tags := map[string]string{}
	for _, t := range in.Tags {
		tags[aws.ToString(t.TagKey)] = aws.ToString(t.TagValue)
	}
	f.keys[arn] = &Key{ARN: arn, Private: priv, Tags: tags}
	return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{Arn: aws.String(arn), KeyId: aws.String(arn)}}, nil
}

func (f *KMS) key(id string) (*Key, error) {
	k, ok := f.keys[id]
	if !ok {
		return nil, &types.NotFoundException{Message: aws.String("key not found")}
	}
	if k.PendingDeletion {
		return nil, &types.KMSInvalidStateException{Message: aws.String("key is pending deletion")}
	}
	return k, nil
}

// GetPublicKey returns the key's DER-encoded SubjectPublicKeyInfo.
func (f *KMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, err := f.key(aws.ToString(in.KeyId))
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.Private.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeyId: aws.String(k.ARN), KeySpec: types.KeySpecRsa2048}, nil
}

// Sign signs a SHA-256 digest with RSASSA_PKCS1_V1_5_SHA_256, as KMS does.
func (f *KMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.SignCalls++
	if err := f.FailSign; err != nil {
		f.FailSign = nil
		return nil, err
	}
	if in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		return nil, fmt.Errorf("kmsfake: expected a SHA-256 digest with RSASSA_PKCS1_V1_5_SHA_256")
	}
	if len(in.Message) != 32 {
		return nil, fmt.Errorf("kmsfake: digest must be 32 bytes, got %d", len(in.Message))
	}
	k, err := f.key(aws.ToString(in.KeyId))
	if err != nil {
		return nil, err
	}
	sig, err := rsa.SignPKCS1v15(nil, k.Private, crypto.SHA256, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig, KeyId: aws.String(k.ARN), SigningAlgorithm: in.SigningAlgorithm}, nil
}

// ScheduleKeyDeletion marks a key pending deletion.
func (f *KMS) ScheduleKeyDeletion(_ context.Context, in *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.FailSchedule; err != nil {
		f.FailSchedule = nil
		return nil, err
	}
	k, err := f.key(aws.ToString(in.KeyId))
	if err != nil {
		return nil, err
	}
	k.PendingDeletion, k.DeletionDays = true, aws.ToInt32(in.PendingWindowInDays)
	return &kms.ScheduleKeyDeletionOutput{KeyId: aws.String(k.ARN)}, nil
}
