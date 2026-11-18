// Package secretbox encrypts the few secrets LiteLogin must be able to read
// back, unlike passwords and tokens, which are stored hashed: TOTP secrets,
// and the secrets of identity providers' app registrations.
//
// In Lambda, each kind has its own KMS key. Only the Auth Lambda may use the
// TOTP key; the Admin Lambda may only encrypt with the identity provider
// key, and the Auth Lambda only decrypt. Every secret is bound to an
// encryption context (whose it is), so a ciphertext copied to another
// user's or provider's item doesn't decrypt. The local development servers
// and tests use AES-GCM with a key in memory instead.
package secretbox

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Box encrypts and decrypts secrets. The encryption context given to Open
// must be the one given to Seal.
type Box interface {
	Seal(ctx context.Context, plaintext []byte, ec map[string]string) ([]byte, error)
	Open(ctx context.Context, ciphertext []byte, ec map[string]string) ([]byte, error)
}

// LocalDevKey is the key the local development servers (make run-auth and
// make run-admin) seal secrets with. It's fixed, so secrets survive restarts
// while DynamoDB Local keeps the data, and the admin server seals what the
// auth server opens; it protects nothing.
var LocalDevKey = sha256.Sum256([]byte("litelogin local development only"))

// PurposeIDPSecret is the encryption context's purpose for identity provider
// secrets. The KMS key policies allow the key's use only with it.
const PurposeIDPSecret = "idp_secret"

// IDPContext is the encryption context of an identity provider's secrets:
// they open only for the provider and pool they were sealed for.
func IDPContext(poolID, idpID string) map[string]string {
	return map[string]string{"purpose": PurposeIDPSecret, "pool_id": poolID, "idp_id": idpID}
}

// ErrOpen is returned when a ciphertext doesn't decrypt: it's damaged, or
// the encryption context differs.
var ErrOpen = errors.New("secretbox: can't decrypt")

// KMSAPI is the part of the KMS client a KMS box uses.
type KMSAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KMS encrypts with a symmetric KMS key. A secret is at most 4 KiB, which
// KMS encrypts directly, without a data key.
type KMS struct {
	Client KMSAPI
	// KeyID is the key's ARN or alias.
	KeyID string
}

// Seal encrypts plaintext with the key.
func (k *KMS) Seal(ctx context.Context, plaintext []byte, ec map[string]string) ([]byte, error) {
	out, err := k.Client.Encrypt(ctx, &kms.EncryptInput{
		KeyId: aws.String(k.KeyID), Plaintext: plaintext, EncryptionContext: ec,
	})
	if err != nil {
		return nil, fmt.Errorf("secretbox: KMS encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

// Open decrypts a ciphertext from Seal. It names the key, so a ciphertext
// made with another key is refused.
func (k *KMS) Open(ctx context.Context, ciphertext []byte, ec map[string]string) ([]byte, error) {
	out, err := k.Client.Decrypt(ctx, &kms.DecryptInput{
		KeyId: aws.String(k.KeyID), CiphertextBlob: ciphertext, EncryptionContext: ec,
	})
	if err != nil {
		var invalid interface{ ErrorCode() string }
		if errors.As(err, &invalid) && (invalid.ErrorCode() == "InvalidCiphertextException" || invalid.ErrorCode() == "IncorrectKeyException") {
			return nil, ErrOpen
		}
		return nil, fmt.Errorf("secretbox: KMS decrypt: %w", err)
	}
	return out.Plaintext, nil
}

// Local encrypts with AES-256-GCM and a key it holds, binding the
// encryption context as additional data. It's for the local development
// server and tests.
type Local struct {
	aead cipher.AEAD
}

// NewLocal returns a Local box with a 32-byte key.
func NewLocal(key []byte) (*Local, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: the key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Local{aead: aead}, nil
}

// Seal encrypts plaintext: a random nonce followed by the sealed data.
func (l *Local) Seal(_ context.Context, plaintext []byte, ec map[string]string) ([]byte, error) {
	nonce := make([]byte, l.aead.NonceSize(), l.aead.NonceSize()+len(plaintext)+l.aead.Overhead())
	_, _ = rand.Read(nonce) // crypto/rand.Read never fails
	return l.aead.Seal(nonce, nonce, plaintext, additionalData(ec)), nil
}

// Open decrypts a ciphertext from Seal.
func (l *Local) Open(_ context.Context, ciphertext []byte, ec map[string]string) ([]byte, error) {
	n := l.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, ErrOpen
	}
	out, err := l.aead.Open(nil, ciphertext[:n], ciphertext[n:], additionalData(ec))
	if err != nil {
		return nil, ErrOpen
	}
	return out, nil
}

// additionalData is the encryption context in a canonical form: sorted
// "key=value" lines. Keys and values never contain newlines.
func additionalData(ec map[string]string) []byte {
	keys := make([]string, 0, len(ec))
	for k := range ec {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + ec[k] + "\n")
	}
	return []byte(b.String())
}
