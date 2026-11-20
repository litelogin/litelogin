// Package email sends LiteLogin's transactional email: email
// verification, password reset, "you already have an account", admin
// invites, and confirming a new email address.
package email

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	htmltemplate "html/template"
	"io"
	"net/mail"
	"strings"
	"sync"
	texttemplate "text/template"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// Message is one email.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender sends email.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Kind is a kind of message.
type Kind string

// Message kinds.
const (
	VerifyEmail       Kind = "verify_email"
	ResetPassword     Kind = "reset_password"
	AlreadyRegistered Kind = "already_registered"
	Invite            Kind = "invite"
	ChangeEmail       Kind = "change_email"
	PasskeyAdded      Kind = "passkey_added"

	// Security notices: what changed on the account, sent to the user's
	// address. They share one template (security_notice).
	MFAEnabled            Kind = "mfa_enabled"
	MFADisabled           Kind = "mfa_disabled"
	MFAReset              Kind = "mfa_reset"
	RecoveryCodeUsed      Kind = "recovery_code_used"
	RecoveryCodesReplaced Kind = "recovery_codes_replaced"
	MFALocked             Kind = "mfa_locked"
	IdentityLinked        Kind = "identity_linked"
	IdentityUnlinked      Kind = "identity_unlinked"
	PasswordSet           Kind = "password_set"
)

const securityNotice = "security_notice"

// notice is a security notice's heading and body, templates of Data.
type notice struct{ heading, body string }

const unexpected = " If you did this, there's nothing to do. If you didn't, someone else may have your password: " +
	"open your account page and change it."

var notices = map[Kind]notice{
	MFAEnabled: {"Two-factor sign-in is on",
		"Two-factor sign-in was turned on for your {{.Brand}} account. Signing in with your password now also takes " +
			"a code from your authenticator app, or a recovery code." + unexpected},
	MFADisabled: {"Two-factor sign-in is off",
		"Two-factor sign-in was turned off for your {{.Brand}} account. Signing in now takes only your password." + unexpected},
	MFAReset: {"Two-factor sign-in was reset",
		"An administrator turned off two-factor sign-in for your {{.Brand}} account, and signed you out everywhere. " +
			"Signing in now takes only your password. If you didn't ask for this, contact the administrator, then " +
			"change your password and turn two-factor sign-in on again."},
	RecoveryCodeUsed: {"A recovery code was used",
		"A recovery code was used to sign in to your {{.Brand}} account. You have {{.Count}} left; each works once. " +
			"If you've lost your authenticator app, set up two-factor sign-in again from your account page." + unexpected},
	RecoveryCodesReplaced: {"You have new recovery codes",
		"New recovery codes were made for your {{.Brand}} account. The old ones no longer work." + unexpected},
	MFALocked: {"Someone has your password",
		"Someone signed in to your {{.Brand}} account with your correct password, then entered wrong two-factor codes " +
			"too many times, so two-factor sign-in is paused for a while. If it wasn't you, change your password now."},
	IdentityLinked: {"You can sign in with {{.Name}}",
		"Your {{.Name}} account was linked to your {{.Brand}} account, so you can sign in with it." + unlinkHint},
	IdentityUnlinked: {"{{.Name}} was removed from your account",
		"Your {{.Name}} account was unlinked from your {{.Brand}} account, so you can't sign in with it any more, " +
			"and you were signed out everywhere else." + unexpected},
	PasswordSet: {"Your account has a password",
		"A password was set on your {{.Brand}} account, so you can sign in with your email and password too." + unexpected},
}

const unlinkHint = " If you didn't do this, someone else may be signed in to your account: open your account page, remove it and sign out everywhere."

var subjects = map[Kind]string{ //nolint:gosec // email subjects, not credentials
	VerifyEmail:       "Verify your email for {{.Brand}}",
	ResetPassword:     "Reset your {{.Brand}} password",
	AlreadyRegistered: "You already have a {{.Brand}} account",
	Invite:            "You've been invited to {{.Brand}}",
	ChangeEmail:       "Confirm your new email for {{.Brand}}",
	PasskeyAdded:      "A passkey was added to your {{.Brand}} account",

	MFAEnabled:            "Two-factor sign-in is on for your {{.Brand}} account",
	MFADisabled:           "Two-factor sign-in is off for your {{.Brand}} account",
	MFAReset:              "Two-factor sign-in was reset on your {{.Brand}} account",
	RecoveryCodeUsed:      "A recovery code was used on your {{.Brand}} account",
	RecoveryCodesReplaced: "New recovery codes for your {{.Brand}} account",
	MFALocked:             "Someone has your {{.Brand}} password",
	IdentityLinked:        "{{.Name}} was linked to your {{.Brand}} account",
	IdentityUnlinked:      "{{.Name}} was removed from your {{.Brand}} account",
	PasswordSet:           "A password was set on your {{.Brand}} account",
}

// Data fills a message template.
type Data struct {
	Brand   string // the client's name, or the org's name
	Host    string // the login host the link points to
	Link    string // the action link (verification, reset), or the account page
	Name    string // a passkey's name, or an identity provider's
	Expires string // how long the link works, e.g. "24 hours"
	Count   int    // how many recovery codes are left

	// Heading and Body are set by Render for security notices.
	Heading, Body string
}

//go:embed templates/*
var templateFS embed.FS

var (
	parseOnce sync.Once
	texts     *texttemplate.Template
	htmls     *htmltemplate.Template
	parseErr  error
)

func parse() error {
	parseOnce.Do(func() {
		texts, parseErr = texttemplate.ParseFS(templateFS, "templates/*.txt")
		if parseErr == nil {
			htmls, parseErr = htmltemplate.ParseFS(templateFS, "templates/*.html")
		}
	})
	return parseErr
}

// Render builds a message of the given kind to to.
func Render(kind Kind, to string, d Data) (Message, error) {
	if err := parse(); err != nil {
		return Message{}, err
	}
	subj, ok := subjects[kind]
	if !ok {
		return Message{}, fmt.Errorf("email: unknown kind %q", kind)
	}
	var s, t, h bytes.Buffer
	if err := execText(&s, subj, d); err != nil {
		return Message{}, err
	}
	name := string(kind)
	if n, ok := notices[kind]; ok {
		name = securityNotice
		var heading, body bytes.Buffer
		if err := execText(&heading, n.heading, d); err != nil {
			return Message{}, err
		}
		if err := execText(&body, n.body, d); err != nil {
			return Message{}, err
		}
		d.Heading, d.Body = heading.String(), body.String()
	}
	if err := texts.ExecuteTemplate(&t, name+".txt", d); err != nil {
		return Message{}, err
	}
	if err := htmls.ExecuteTemplate(&h, name+".html", d); err != nil {
		return Message{}, err
	}
	// A brand name is operator-controlled, but keep header injection out
	// of the subject regardless.
	subject := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s.String())
	return Message{To: to, Subject: subject, Text: t.String(), HTML: h.String()}, nil
}

// execText executes a text template of Data.
func execText(w *bytes.Buffer, tmpl string, d Data) error {
	t, err := texttemplate.New("").Parse(tmpl)
	if err != nil {
		return err
	}
	return t.Execute(w, d)
}

// SESAPI is the part of the SES v2 client SES uses.
type SESAPI interface {
	SendEmail(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

// SES sends email through Amazon SES.
type SES struct {
	Client SESAPI
	// From is the sender address, e.g. no-reply@login.example.com. Its
	// domain is a verified SES identity.
	From string
	// FromName is the display name; the message's brand is used if empty.
	FromName string
	// ConfigurationSet records delivery events and applies suppression.
	ConfigurationSet string
}

// Send implements Sender.
func (s *SES) Send(ctx context.Context, m Message) error {
	from := (&mail.Address{Name: s.FromName, Address: s.From}).String()
	in := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(from),
		Destination:      &sestypes.Destination{ToAddresses: []string{m.To}},
		Content: &sestypes.EmailContent{Simple: &sestypes.Message{
			Subject: &sestypes.Content{Data: aws.String(m.Subject), Charset: aws.String("UTF-8")},
			Body: &sestypes.Body{
				Text: &sestypes.Content{Data: aws.String(m.Text), Charset: aws.String("UTF-8")},
				Html: &sestypes.Content{Data: aws.String(m.HTML), Charset: aws.String("UTF-8")},
			},
		}},
	}
	if s.ConfigurationSet != "" {
		in.ConfigurationSetName = aws.String(s.ConfigurationSet)
	}
	if _, err := s.Client.SendEmail(ctx, in); err != nil {
		return fmt.Errorf("email: send: %w", err)
	}
	return nil
}

// Printer writes messages to W instead of sending them: for the local
// development server only, since the output contains one-time links.
type Printer struct {
	W  io.Writer
	mu sync.Mutex
}

// Send implements Sender.
func (p *Printer) Send(_ context.Context, m Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := fmt.Fprintf(p.W, "\n----- email (local development: not sent) -----\nTo: %s\nSubject: %s\n\n%s\n-----------------------------------------------\n",
		m.To, m.Subject, m.Text)
	return err
}

// Recorder keeps messages in memory, for tests.
type Recorder struct {
	mu       sync.Mutex
	messages []Message
	// Err, if set, is returned by Send instead of recording.
	Err error
}

// Send implements Sender.
func (r *Recorder) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Err != nil {
		return r.Err
	}
	r.messages = append(r.messages, m)
	return nil
}

// Messages returns the messages sent so far.
func (r *Recorder) Messages() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Message(nil), r.messages...)
}
