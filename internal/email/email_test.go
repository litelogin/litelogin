package email

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

func TestRender(t *testing.T) {
	d := Data{Brand: "Acme <b>Portal</b>\r\nBcc: x@evil.example", Host: "portal.example.com", Link: "https://portal.example.com/verify-email?token=abc&x=1", Expires: "24 hours"}
	for _, k := range []Kind{VerifyEmail, ResetPassword, AlreadyRegistered, Invite} {
		m, err := Render(k, "a@example.com", d)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if strings.ContainsAny(m.Subject, "\r\n") {
			t.Errorf("%s: subject has a line break: %q", k, m.Subject)
		}
		if !strings.Contains(m.Text, d.Link) {
			t.Errorf("%s: text lacks the link", k)
		}
		if !strings.Contains(m.HTML, "token=abc&amp;x=1") || strings.Contains(m.HTML, "<b>Portal") {
			t.Errorf("%s: HTML not escaped:\n%s", k, m.HTML)
		}
	}
	if _, err := Render("nope", "a@example.com", d); err == nil {
		t.Error("unknown kind rendered")
	}
}

type fakeSES struct{ in *sesv2.SendEmailInput }

func (f *fakeSES) SendEmail(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.in = in
	return &sesv2.SendEmailOutput{}, nil
}

func TestSES(t *testing.T) {
	f := &fakeSES{}
	s := &SES{Client: f, From: "no-reply@dev.litelogin.com", FromName: "LiteLogin", ConfigurationSet: "cs"}
	if err := s.Send(context.Background(), Message{To: "a@example.com", Subject: "Hi", Text: "t", HTML: "h"}); err != nil {
		t.Fatal(err)
	}
	if *f.in.FromEmailAddress != `"LiteLogin" <no-reply@dev.litelogin.com>` || *f.in.ConfigurationSetName != "cs" || f.in.Destination.ToAddresses[0] != "a@example.com" {
		t.Errorf("SendEmail input: from %q, set %q", *f.in.FromEmailAddress, *f.in.ConfigurationSetName)
	}
}
