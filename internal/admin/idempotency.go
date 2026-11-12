package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/litelogin/litelogin/internal/store"
)

const maxIdempotencyKeyLen = 255

// idempotent runs a request that can change data. Without an
// Idempotency-Key it just runs it. With one, a retry with the same key and
// request returns the original response (Datamodel.md, "Admin: idempotent
// requests"). It reports whether the response was a replay.
func (s *Server) idempotent(h func(http.ResponseWriter, *http.Request) error, w *recorder, r *http.Request) bool {
	idemKey := r.Header.Get("Idempotency-Key")
	if idemKey == "" {
		s.run(h, w, r)
		return false
	}
	if len(idemKey) > maxIdempotencyKeyLen {
		writeError(w, errInvalid("Idempotency-Key is longer than %d characters", maxIdempotencyKeyLen))
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, toAPIError(err))
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	hash := requestHash(r, body)
	ctx, caller := r.Context(), callerARN(r.Context())

	rec, err := s.Store.BeginIdempotentRequest(ctx, caller, idemKey, hash)
	if err != nil {
		s.log().ErrorContext(ctx, "begin idempotent request", "error", err)
		writeError(w, toAPIError(err))
		return false
	}
	switch rec.Outcome {
	case store.IdempotencyMismatch:
		writeError(w, &apiError{Status: http.StatusUnprocessableEntity, Code: "idempotency_key_reused",
			Message: "this Idempotency-Key was used for a different request"})
		return false
	case store.IdempotencyInProgress:
		writeError(w, errConflict("request_in_progress",
			"a request with this Idempotency-Key is still in progress; retry shortly"))
		return false
	case store.IdempotencyCompleted:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(rec.ResponseStatus)
		_, _ = w.Write(rec.ResponseBody)
		return true
	}

	s.run(h, w, r)

	// Release the key after a failure, so the caller can fix the problem
	// and retry with the same key. Every operation is a single conditional
	// write or transaction, so a failed request changed nothing.
	if w.status() >= 300 {
		if err := s.Store.ReleaseIdempotentRequest(ctx, caller, idemKey, hash); err != nil {
			s.log().ErrorContext(ctx, "release idempotent request", "error", err)
		}
		return false
	}
	stored := w.body.Bytes()
	if w.replay != nil {
		stored = w.replay
	}
	if err := s.Store.CompleteIdempotentRequest(ctx, caller, idemKey, hash, w.status(), stored); err != nil {
		// The change happened and the caller has the response. A retry
		// with this key gets 409 until the record expires.
		s.log().ErrorContext(ctx, "complete idempotent request", "error", err)
	}
	return false
}

// requestHash identifies a request: SHA-256 of its method, path, query,
// If-Match and body.
func requestHash(r *http.Request, body []byte) string {
	h := sha256.New()
	for _, part := range []string{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("If-Match")} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
