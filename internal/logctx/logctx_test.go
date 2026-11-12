package logctx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&buf, nil))).With("service", "auth")

	ctx := New(context.Background(), slog.String(RequestID, "req-1"))
	Set(ctx, OrgID, "org-1")
	Set(ctx, OrgID, "org-2") // replaces
	Set(ctx, ClientID, "")   // ignored
	log.InfoContext(ctx, "hello", ClientID, "own-client")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got[RequestID] != "req-1" || got[OrgID] != "org-2" || got[ClientID] != "own-client" || got["service"] != "auth" {
		t.Errorf("line = %s", buf.String())
	}

	// Without New, nothing is added and Set does nothing.
	buf.Reset()
	Set(context.Background(), OrgID, "x")
	log.InfoContext(context.Background(), "plain")
	if bytes.Contains(buf.Bytes(), []byte(OrgID)) {
		t.Errorf("line = %s", buf.String())
	}
}
