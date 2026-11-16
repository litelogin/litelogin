package secretbox

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var ec = map[string]string{"purpose": "totp", "pool_id": "p1", "user_id": "u1"}

func TestLocal(t *testing.T) {
	ctx := context.Background()
	box, err := NewLocal(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("12345678901234567890")
	c1, _ := box.Seal(ctx, secret, ec)
	c2, _ := box.Seal(ctx, secret, ec)
	if bytes.Equal(c1, c2) || bytes.Contains(c1, secret) {
		t.Fatal("ciphertexts repeat or contain the secret")
	}
	got, err := box.Open(ctx, c1, ec)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %q, %v", got, err)
	}

	// Another user's context, a damaged ciphertext or another key: no.
	other := maps.Clone(ec)
	other["user_id"] = "u2"
	if _, err := box.Open(ctx, c1, other); !errors.Is(err, ErrOpen) {
		t.Errorf("other context: %v", err)
	}
	bad := bytes.Clone(c1)
	bad[len(bad)-1] ^= 1
	if _, err := box.Open(ctx, bad, ec); !errors.Is(err, ErrOpen) {
		t.Errorf("damaged: %v", err)
	}
	if _, err := box.Open(ctx, []byte{1, 2}, ec); !errors.Is(err, ErrOpen) {
		t.Errorf("short: %v", err)
	}
	box2, _ := NewLocal(bytes.Repeat([]byte{8}, 32))
	if _, err := box2.Open(ctx, c1, ec); !errors.Is(err, ErrOpen) {
		t.Errorf("other key: %v", err)
	}
	if _, err := NewLocal([]byte("short")); err == nil {
		t.Error("a short key was accepted")
	}
}

// fakeKMS checks what the KMS box sends, and "encrypts" by prefixing.
type fakeKMS struct {
	keyID string
	ec    map[string]string
}

func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if aws.ToString(in.KeyId) != f.keyID || !maps.Equal(in.EncryptionContext, f.ec) {
		return nil, errors.New("wrong key or context")
	}
	return &kms.EncryptOutput{CiphertextBlob: append([]byte("ct:"), in.Plaintext...)}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if aws.ToString(in.KeyId) != f.keyID {
		return nil, &types.IncorrectKeyException{Message: aws.String("wrong key")}
	}
	if !maps.Equal(in.EncryptionContext, f.ec) || !bytes.HasPrefix(in.CiphertextBlob, []byte("ct:")) {
		return nil, &types.InvalidCiphertextException{Message: aws.String("invalid")}
	}
	return &kms.DecryptOutput{Plaintext: in.CiphertextBlob[3:]}, nil
}

func TestKMS(t *testing.T) {
	ctx := context.Background()
	f := &fakeKMS{keyID: "alias/litelogin-dev-mfa", ec: ec}
	box := &KMS{Client: f, KeyID: f.keyID}
	c, err := box.Seal(ctx, []byte("s"), ec)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := box.Open(ctx, c, ec); err != nil || string(got) != "s" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	other := maps.Clone(ec)
	other["user_id"] = "u2"
	if _, err := box.Open(ctx, c, other); !errors.Is(err, ErrOpen) {
		t.Errorf("other context: %v", err)
	}
	if _, err := (&KMS{Client: f, KeyID: "alias/other"}).Open(ctx, c, ec); !errors.Is(err, ErrOpen) {
		t.Errorf("other key: %v", err)
	}
}
