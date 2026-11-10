package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// One-time token purposes.
const (
	PurposeVerifyEmail   = "verify_email"
	PurposeResetPassword = "reset_password"
	PurposeChangeEmail   = "change_email"
)

// OneTimeToken is an emailed link token: OTT#{token_hash} / DETAILS.
type OneTimeToken struct {
	Hash      string `dynamodbav:"-"`
	Purpose   string `dynamodbav:"purpose"`
	PoolID    string `dynamodbav:"pool_id"`
	UserID    string `dynamodbav:"user_id"`
	Email     string `dynamodbav:"email"`               // the user's email when the token was sent
	NewEmail  string `dynamodbav:"new_email,omitempty"` // change_email only
	ExpiresAt int64  `dynamodbav:"expires_at"`
}

type ottItem struct {
	keys
	OneTimeToken
}

func ottKey(hash string) map[string]types.AttributeValue { return key(pfxOTT+hash, skDetails) }

// CreateOneTimeToken stores a one-time token that expires after lifetime.
// Emails are normalized.
func (s *Store) CreateOneTimeToken(ctx context.Context, t *OneTimeToken, lifetime time.Duration) error {
	switch t.Purpose {
	case PurposeVerifyEmail, PurposeResetPassword:
		if t.NewEmail != "" {
			return errors.New("store: new_email is only for change_email tokens")
		}
	case PurposeChangeEmail:
		e, err := NormalizeEmail(t.NewEmail)
		if err != nil {
			return err
		}
		t.NewEmail = e
	default:
		return fmt.Errorf("store: unknown one-time token purpose %q", t.Purpose)
	}
	e, err := NormalizeEmail(t.Email)
	if err != nil {
		return err
	}
	if t.Hash == "" || t.UserID == "" || t.PoolID == "" {
		return errors.New("store: token hash, user ID and pool ID are required")
	}
	t.Email = e
	t.ExpiresAt = s.now().Add(lifetime).Unix()
	item, err := marshal(ottItem{keys: keys{pfxOTT + t.Hash, skDetails}, OneTimeToken: *t})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// GetOneTimeToken returns an unexpired one-time token with this purpose.
func (s *Store) GetOneTimeToken(ctx context.Context, hash, purpose string) (*OneTimeToken, error) {
	var it ottItem
	if err := s.get(ctx, s.session, ottKey(hash), &it); err != nil {
		return nil, err
	}
	if it.Purpose != purpose || it.ExpiresAt <= s.unix() {
		return nil, ErrNotFound
	}
	it.Hash = hash
	return &it.OneTimeToken, nil
}

// consumeOTT is the transaction item that deletes a token, if it still has
// this purpose and hasn't expired. Exactly one concurrent consumer wins.
func (s *Store) consumeOTT(hash, purpose string) types.TransactWriteItem {
	return del(s.session, ottKey(hash), "#purpose = :purpose AND #expires_at > :now", names("purpose", "expires_at"),
		map[string]types.AttributeValue{":purpose": avS(purpose), ":now": avN(s.unix())})
}

// VerifyEmail consumes a verify_email token and marks the user's email
// verified, if the user's email is still the one the token was sent to. It
// returns the user ID, or ErrNotFound if the link is invalid or expired.
func (s *Store) VerifyEmail(ctx context.Context, hash string) (string, error) {
	t, err := s.GetOneTimeToken(ctx, hash, PurposeVerifyEmail)
	if err != nil {
		return "", err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		s.consumeOTT(hash, PurposeVerifyEmail),
		update(s.config, userKey(t.UserID), "SET #email_verified = :true, #updated_at = :now", "#email = :email",
			names("email_verified", "updated_at", "email"),
			map[string]types.AttributeValue{":true": avB(true), ":now": avN(s.unix()), ":email": avS(t.Email)}),
	})
	if asTxFailure(err) != nil {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return t.UserID, nil
}

// CompletePasswordReset consumes a reset_password token and sets the new
// password hash. It also marks the email verified (the user just proved they
// own it), clears the lockout, and increments auth_version, revoking every
// credential. Run CleanupUserCredentials afterwards.
//
// It returns the user ID, or ErrNotFound if the link is invalid, expired, or
// was sent to an email the user no longer has.
func (s *Store) CompletePasswordReset(ctx context.Context, hash, newPasswordHash string) (string, error) {
	t, err := s.GetOneTimeToken(ctx, hash, PurposeResetPassword)
	if err != nil {
		return "", err
	}
	now := s.unix()
	err = s.transact(ctx, []types.TransactWriteItem{
		s.consumeOTT(hash, PurposeResetPassword),
		update(s.config, userKey(t.UserID),
			"SET #password_hash = :hash, #password_updated_at = :now, #updated_at = :now, #email_verified = :true, "+
				"#failed_login_count = :zero REMOVE #locked_until ADD #auth_version :one, #version :one",
			"#email = :email",
			names("password_hash", "password_updated_at", "updated_at", "email_verified", "failed_login_count",
				"locked_until", "auth_version", "version", "email"),
			map[string]types.AttributeValue{
				":hash": avS(newPasswordHash), ":now": avN(now), ":true": avB(true), ":zero": avN(0),
				":one": avN(1), ":email": avS(t.Email),
			}),
	})
	if asTxFailure(err) != nil {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return t.UserID, nil
}

// ConfirmEmailChange consumes a change_email token and moves the user to the
// new email: it reserves the new email in the pool, releases the old one,
// and marks the new email verified. It returns the user ID, ErrEmailTaken if
// the new email is registered to another user in the meantime, or
// ErrNotFound if the link is invalid or expired.
func (s *Store) ConfirmEmailChange(ctx context.Context, hash string) (string, error) {
	t, err := s.GetOneTimeToken(ctx, hash, PurposeChangeEmail)
	if err != nil {
		return "", err
	}
	newEmail, err := marshal(emailItem{keys: keys{emailPK(t.PoolID, t.NewEmail), skEmail}, UserID: t.UserID})
	if err != nil {
		return "", err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		s.consumeOTT(hash, PurposeChangeEmail),
		put(s.config, newEmail, "attribute_not_exists(PK)", nil, nil),
		del(s.config, emailKey(t.PoolID, t.Email), "#user_id = :user", names("user_id"),
			map[string]types.AttributeValue{":user": avS(t.UserID)}),
		update(s.config, userKey(t.UserID),
			"SET #email = :new, GSI1SK = :sk, #email_verified = :true, #updated_at = :now ADD #version :one",
			"#email = :old", names("email", "email_verified", "updated_at", "version"),
			map[string]types.AttributeValue{
				":new": avS(t.NewEmail), ":sk": avS(pfxEmailSK + t.NewEmail), ":true": avB(true),
				":now": avN(s.unix()), ":one": avN(1), ":old": avS(t.Email),
			}),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(1) && !f.failed(0) {
			return "", ErrEmailTaken
		}
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return t.UserID, nil
}
