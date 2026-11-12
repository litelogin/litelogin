// Package logctx puts a request's identifiers on every log line written
// while handling it (Architecture.md, "Observability": a request ID, org
// ID and client ID on every line).
//
// A request starts with New, which gives its context a set of fields;
// handlers add to it with Set as they learn more (the org once the login
// host resolves, the client once it's known), and Handler copies the
// fields onto each record logged with that context.
package logctx

import (
	"context"
	"log/slog"
	"sync"
)

// Field names.
const (
	RequestID = "request_id"
	OrgID     = "org_id"
	ClientID  = "client_id"
	Host      = "host"
)

type key struct{}

type fields struct {
	mu    sync.Mutex
	attrs []slog.Attr
}

// New returns ctx with an empty set of fields, plus attrs.
func New(ctx context.Context, attrs ...slog.Attr) context.Context {
	return context.WithValue(ctx, key{}, &fields{attrs: attrs})
}

// Set sets a field on ctx's request, replacing any value it had. It does
// nothing if ctx has no fields (New wasn't called) or value is empty.
func Set(ctx context.Context, name, value string) {
	f, ok := ctx.Value(key{}).(*fields)
	if !ok || value == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, a := range f.attrs {
		if a.Key == name {
			f.attrs[i] = slog.String(name, value)
			return
		}
	}
	f.attrs = append(f.attrs, slog.String(name, value))
}

func attrs(ctx context.Context) []slog.Attr {
	f, ok := ctx.Value(key{}).(*fields)
	if !ok {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]slog.Attr(nil), f.attrs...)
}

// Handler adds the context's fields to each record. A field the record
// sets itself (e.g. client_id) is kept as the record has it.
type Handler struct{ slog.Handler }

// NewHandler wraps h.
func NewHandler(h slog.Handler) *Handler { return &Handler{h} }

// Handle adds the fields and passes the record on.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if extra := attrs(ctx); len(extra) > 0 {
		own := map[string]bool{}
		r.Attrs(func(a slog.Attr) bool {
			own[a.Key] = true
			return true
		})
		for _, a := range extra {
			if !own[a.Key] {
				r.AddAttrs(a)
			}
		}
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs keeps the wrapper around the derived handler.
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler { return &Handler{h.Handler.WithAttrs(as)} }

// WithGroup keeps the wrapper around the derived handler.
func (h *Handler) WithGroup(name string) slog.Handler { return &Handler{h.Handler.WithGroup(name)} }
