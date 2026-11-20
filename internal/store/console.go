package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ---- Admin console ----
//
// The admin console is a client of LiteLogin: it signs its admins in on
// the console org's login host, and keeps its own sessions. Both items are
// in the Session table, with TTL.

const (
	pfxConsoleLogin   = "CONSOLE_LOGIN#"
	pfxConsoleSession = "CONSOLE_SESSION#"
)

// ConsoleLogin is a console sign-in in progress:
// CONSOLE_LOGIN#{state_hash} / DETAILS. The state parameter is a random
// token, stored hashed. It works once, from the browser that started it.
type ConsoleLogin struct {
	Hash string `dynamodbav:"-"`
	// Nonce must come back in the ID token.
	Nonce string `dynamodbav:"nonce"`
	// Verifier is the PKCE code verifier (RFC 7636).
	Verifier string `dynamodbav:"verifier"`
	// BrowserHash is the hash of the browser's sign-in cookie: the
	// callback must come from the browser that started it (no login
	// CSRF).
	BrowserHash string `dynamodbav:"browser_hash"`
	// ReturnTo is the console path to go to after signing in.
	ReturnTo  string `dynamodbav:"return_to,omitempty"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
}

type consoleLoginItem struct {
	keys
	ConsoleLogin
}

// CreateConsoleLogin stores a console sign-in that expires after lifetime.
func (s *Store) CreateConsoleLogin(ctx context.Context, l *ConsoleLogin, lifetime time.Duration) error {
	if l.Hash == "" || l.Nonce == "" || l.Verifier == "" || l.BrowserHash == "" {
		return errors.New("store: incomplete console sign-in")
	}
	l.ExpiresAt = s.now().Add(lifetime).Unix()
	item, err := marshal(consoleLoginItem{keys: keys{pfxConsoleLogin + l.Hash, skDetails}, ConsoleLogin: *l})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// ConsumeConsoleLogin deletes a console sign-in and returns it, if it
// hasn't expired. Exactly one concurrent consumer gets it; the others, and
// any later attempt, get ErrNotFound.
func (s *Store) ConsumeConsoleLogin(ctx context.Context, hash string) (*ConsoleLogin, error) {
	out, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(s.session),
		Key:                       key(pfxConsoleLogin+hash, skDetails),
		ConditionExpression:       aws.String("#expires_at > :now"),
		ExpressionAttributeNames:  names("expires_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": avN(s.unix())},
		ReturnValues:              types.ReturnValueAllOld,
	})
	if ok, _ := conditionFailed(err); ok {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: consume console sign-in: %w", err)
	}
	var it consoleLoginItem
	if err := unmarshal(out.Attributes, &it); err != nil {
		return nil, err
	}
	it.Hash = hash
	return &it.ConsoleLogin, nil
}

// ConsoleSession is a signed-in console admin:
// CONSOLE_SESSION#{session_hash} / DETAILS. It's valid only while the
// user's auth_version is still AuthVersion, so disabling the user or
// logging them out everywhere ends it.
type ConsoleSession struct {
	Hash        string   `dynamodbav:"-"`
	UserID      string   `dynamodbav:"user_id"`
	Email       string   `dynamodbav:"email"`
	AuthVersion int64    `dynamodbav:"auth_version"`
	AuthTime    int64    `dynamodbav:"auth_time"`
	AMR         []string `dynamodbav:"amr,omitempty"`
	// IDToken is the ID token of the sign-in, the id_token_hint of the
	// logout that ends it.
	IDToken       string `dynamodbav:"id_token"`
	CreatedAt     int64  `dynamodbav:"created_at"`
	LastSeenAt    int64  `dynamodbav:"last_seen_at"`
	IdleExpiresAt int64  `dynamodbav:"idle_expires_at"`
	ExpiresAt     int64  `dynamodbav:"expires_at"`
}

type consoleSessionItem struct {
	keys
	ConsoleSession
}

func consoleSessionKey(hash string) map[string]types.AttributeValue {
	return key(pfxConsoleSession+hash, skDetails)
}

// CreateConsoleSession creates a console session that expires after
// lifetime, or after idle without activity.
func (s *Store) CreateConsoleSession(ctx context.Context, sess *ConsoleSession, lifetime, idle time.Duration) error {
	if sess.Hash == "" || sess.UserID == "" || sess.AuthVersion == 0 {
		return errors.New("store: console session hash, user ID and auth_version are required")
	}
	now := s.now()
	sess.CreatedAt, sess.LastSeenAt = now.Unix(), now.Unix()
	sess.ExpiresAt = now.Add(lifetime).Unix()
	sess.IdleExpiresAt = min(now.Add(idle).Unix(), sess.ExpiresAt)
	item, err := marshal(consoleSessionItem{keys: keys{pfxConsoleSession + sess.Hash, skDetails}, ConsoleSession: *sess})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// GetConsoleSession returns a console session that hasn't expired. It
// doesn't check the user: callers compare AuthVersion with the user's.
func (s *Store) GetConsoleSession(ctx context.Context, hash string) (*ConsoleSession, error) {
	var it consoleSessionItem
	if err := s.get(ctx, s.session, consoleSessionKey(hash), &it); err != nil {
		return nil, err
	}
	now := s.unix()
	if it.ExpiresAt <= now || it.IdleExpiresAt <= now {
		return nil, ErrNotFound
	}
	it.Hash = hash
	return &it.ConsoleSession, nil
}

// TouchConsoleSession records activity, as TouchSession does: at most once
// every SessionTouchInterval it moves last_seen_at to now and
// idle_expires_at to now+idle (never past expires_at).
func (s *Store) TouchConsoleSession(ctx context.Context, sess *ConsoleSession, idle time.Duration) error {
	now := s.now()
	if now.Sub(time.Unix(sess.LastSeenAt, 0)) < SessionTouchInterval {
		return nil
	}
	idleExpires := min(now.Add(idle).Unix(), sess.ExpiresAt)
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.session),
		Key:                      consoleSessionKey(sess.Hash),
		UpdateExpression:         aws.String("SET #last_seen_at = :now, #idle_expires_at = :idle"),
		ConditionExpression:      aws.String("#last_seen_at = :seen"),
		ExpressionAttributeNames: names("last_seen_at", "idle_expires_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": avN(now.Unix()), ":idle": avN(idleExpires), ":seen": avN(sess.LastSeenAt),
		},
	})
	if ok, _ := conditionFailed(err); ok {
		return nil // deleted, or touched concurrently
	}
	if err != nil {
		return fmt.Errorf("store: touch console session: %w", err)
	}
	sess.LastSeenAt, sess.IdleExpiresAt = now.Unix(), idleExpires
	return nil
}

// DeleteConsoleSession deletes a console session (sign-out). Deleting a
// missing session succeeds.
func (s *Store) DeleteConsoleSession(ctx context.Context, hash string) error {
	return s.deleteItem(ctx, s.session, consoleSessionKey(hash))
}
