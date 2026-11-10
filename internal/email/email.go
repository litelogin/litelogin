// Package email sends LiteLogin's transactional email: email
// verification, password reset, "you already have an account", and
// admin invites.
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
)

var subjects = map[Kind]string{ //nolint:gosec // email subjects, not credentials
	VerifyEmail:       "Verify your email for {{.Brand}}",
	ResetPassword:     "Reset your {{.Brand}} password",
	AlreadyRegistered: "You already have a {{.Brand}} account",
	Invite:            "You've been invited to {{.Brand}}",
}

// Data fills a message template.
type Data struct {
	Brand   string // the client's name, or its theme's brand name
	Host    string // the login host the link points to
	Link    string // the action link (verification, reset)
	Expires string // how long the link works, e.g. "24 hours"
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
	st, err := texttemplate.New("subject").Parse(subj)
	if err != nil {
		return Message{}, err
	}
	if err := st.Execute(&s, d); err != nil {
		return Message{}, err
	}
	if err := texts.ExecuteTemplate(&t, string(kind)+".txt", d); err != nil {
		return Message{}, err
	}
	if err := htmls.ExecuteTemplate(&h, string(kind)+".html", d); err != nil {
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

// SESAPI is the part of the SES v2 client SES uses.
type SESAPI interface {
	SendEmail(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

// SES sends email through Amazon SES.
type SES struct {
	Client SESAPI
	// From is the sender address, e.g. no-reply@dev.litelogin.com. Its
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
