package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Cursors signs and verifies pagination cursors, so callers can't change
// the DynamoDB key a cursor holds or move it to another listing.
type Cursors interface {
	// Sign wraps a store cursor for the listing identified by scope. An
	// empty store cursor (the last page) stays empty.
	Sign(ctx context.Context, scope, inner string) (string, error)
	// Verify returns the store cursor in a signed cursor issued for scope.
	Verify(ctx context.Context, scope, cursor string) (string, error)
}

func errInvalidCursor() *apiError {
	return errInvalid("invalid cursor: pass next_cursor from the previous page unchanged")
}

// cursorMessage is what a cursor's MAC covers.
func cursorMessage(payload string) []byte {
	return []byte("litelogin-admin-cursor-v1\x00" + payload)
}

func encodeCursorPayload(scope, inner string) string {
	payload, _ := json.Marshal(cursorPayload{Scope: scope, Inner: inner})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// splitCursor parses payload.mac and checks the payload's scope. The MAC
// still has to be verified.
func splitCursor(scope, cursor string) (payload string, mac []byte, inner string, err error) {
	p, sig, ok := strings.Cut(cursor, ".")
	if !ok {
		return "", nil, "", errInvalidCursor()
	}
	mac, err = base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(mac) != sha256.Size {
		return "", nil, "", errInvalidCursor()
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return "", nil, "", errInvalidCursor()
	}
	var cp cursorPayload
	if err := json.Unmarshal(raw, &cp); err != nil || cp.Scope != scope || cp.Inner == "" {
		return "", nil, "", errInvalidCursor()
	}
	return p, mac, cp.Inner, nil
}

// ---- KMS ----

// KMSMAC is the part of the KMS client KMSCursors uses.
type KMSMAC interface {
	GenerateMac(ctx context.Context, in *kms.GenerateMacInput, opts ...func(*kms.Options)) (*kms.GenerateMacOutput, error)
	VerifyMac(ctx context.Context, in *kms.VerifyMacInput, opts ...func(*kms.Options)) (*kms.VerifyMacOutput, error)
}

// KMSCursors signs cursors with a KMS HMAC key (HMAC_256), so the key
// never leaves KMS.
type KMSCursors struct {
	KMS   KMSMAC
	KeyID string
}

var _ Cursors = (*KMSCursors)(nil)

// Sign implements Cursors.
func (c *KMSCursors) Sign(ctx context.Context, scope, inner string) (string, error) {
	if inner == "" {
		return "", nil
	}
	p := encodeCursorPayload(scope, inner)
	out, err := c.KMS.GenerateMac(ctx, &kms.GenerateMacInput{
		KeyId: aws.String(c.KeyID), MacAlgorithm: kmstypes.MacAlgorithmSpecHmacSha256, Message: cursorMessage(p),
	})
	if err != nil {
		return "", fmt.Errorf("sign cursor: %w", err)
	}
	return p + "." + base64.RawURLEncoding.EncodeToString(out.Mac), nil
}

// Verify implements Cursors.
func (c *KMSCursors) Verify(ctx context.Context, scope, cursor string) (string, error) {
	p, mac, inner, err := splitCursor(scope, cursor)
	if err != nil {
		return "", err
	}
	out, err := c.KMS.VerifyMac(ctx, &kms.VerifyMacInput{
		KeyId: aws.String(c.KeyID), MacAlgorithm: kmstypes.MacAlgorithmSpecHmacSha256, Message: cursorMessage(p), Mac: mac,
	})
	var invalid *kmstypes.KMSInvalidMacException
	if errors.As(err, &invalid) || (err == nil && !out.MacValid) {
		return "", errInvalidCursor()
	}
	if err != nil {
		return "", fmt.Errorf("verify cursor: %w", err)
	}
	return inner, nil
}

// ---- Local keys ----

// minCursorKeyLen is the minimum HMAC key length (256 bits).
const minCursorKeyLen = 32

// CursorSigner signs cursors with HMAC-SHA256 keys held in memory: for
// local development and tests. Deployed environments use KMSCursors.
//
// Keys[0] signs; every key verifies, so a key can be rotated by adding the
// new one first.
type CursorSigner struct {
	Keys [][]byte
}

var _ Cursors = (*CursorSigner)(nil)

// NewCursorSigner returns a signer, checking that every key is long enough.
func NewCursorSigner(keys ...[]byte) (*CursorSigner, error) {
	if len(keys) == 0 {
		return nil, errors.New("admin: a cursor key is required")
	}
	for _, k := range keys {
		if len(k) < minCursorKeyLen {
			return nil, errors.New("admin: cursor keys must be at least 32 bytes")
		}
	}
	return &CursorSigner{Keys: keys}, nil
}

type cursorPayload struct {
	Scope string `json:"s"` // the listing the cursor belongs to
	Inner string `json:"c"` // the store's cursor
}

// Sign implements Cursors.
func (c *CursorSigner) Sign(_ context.Context, scope, inner string) (string, error) {
	if inner == "" {
		return "", nil
	}
	p := encodeCursorPayload(scope, inner)
	return p + "." + base64.RawURLEncoding.EncodeToString(c.mac(c.Keys[0], p)), nil
}

// Verify implements Cursors.
func (c *CursorSigner) Verify(_ context.Context, scope, cursor string) (string, error) {
	p, mac, inner, err := splitCursor(scope, cursor)
	if err != nil {
		return "", err
	}
	for _, k := range c.Keys {
		if hmac.Equal(mac, c.mac(k, p)) {
			return inner, nil
		}
	}
	return "", errInvalidCursor()
}

func (c *CursorSigner) mac(key []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(cursorMessage(payload))
	return m.Sum(nil)
}
