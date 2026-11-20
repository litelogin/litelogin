package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/litelogin/litelogin/internal/httpx"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeError(w, AsError(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func writeError(w http.ResponseWriter, e *Error) {
	w.Header().Del("ETag")
	writeJSON(w, e.Status, e)
}

// writeVersioned writes a resource with its version as the ETag.
func writeVersioned(w http.ResponseWriter, status int, version int64, v any) {
	w.Header().Set("ETag", etag(version))
	writeJSON(w, status, v)
}

func etag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

// ifMatch returns the version in the If-Match header. Updates require it:
// it's what stops one operator's update from silently overwriting another's.
func ifMatch(r *http.Request) (int64, error) {
	v, ok, err := optionalIfMatch(r)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, &Error{Status: http.StatusPreconditionRequired, Code: "if_match_required",
			Message: "send If-Match with the ETag from a GET of this resource"}
	}
	return v, nil
}

// optionalIfMatch is ifMatch for actions such as disable, where the
// current version is used if none is sent.
func optionalIfMatch(r *http.Request) (int64, bool, error) {
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseInt(strings.Trim(h, `"`), 10, 64)
	if err != nil || v < 1 || !strings.HasPrefix(h, `"`) || !strings.HasSuffix(h, `"`) {
		return 0, false, errInvalid(`If-Match must be an ETag returned by this API, e.g. "3"`)
	}
	return v, true, nil
}

// decode reads a JSON request body into v. Unknown fields are rejected, so
// a misspelled field fails instead of being ignored.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return err
		}
		if errors.Is(err, io.EOF) {
			return errInvalid("a JSON request body is required")
		}
		return errInvalid("invalid JSON body: %s", strings.TrimPrefix(err.Error(), "json: "))
	}
	if dec.More() {
		return errInvalid("invalid JSON body: unexpected data after the object")
	}
	return nil
}

// recorder remembers the status a handler wrote, and the body to store for
// idempotent replay.
type recorder struct {
	http.ResponseWriter
	code int
	body bytes.Buffer
	// replay, if set, replaces the body stored for replay: responses that
	// carry a secret store a copy without it.
	replay []byte
}

func (r *recorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b) //nolint:gosec // passes through handler output, which is always application/json
}

func (r *recorder) status() int {
	if r.code == 0 {
		return http.StatusOK
	}
	return r.code
}

// writeWithSecret writes a response that contains a secret. For
// idempotent replay, the response is stored as redacted instead.
func writeWithSecret(w http.ResponseWriter, status int, version int64, full, redacted any) {
	if rec, ok := w.(*recorder); ok {
		body, err := json.Marshal(redacted)
		if err == nil {
			rec.replay = append(body, '\n')
		}
	}
	writeVersioned(w, status, version, full)
}

func requestID(r *http.Request) string {
	if rc, ok := httpx.FunctionURLRequestContext(r.Context()); ok {
		return rc.RequestID
	}
	return ""
}

// FunctionURLCaller reads the caller's IAM principal ARN from the function
// URL request context. It's only present when the function URL uses
// AWS_IAM auth.
func FunctionURLCaller(r *http.Request) (string, bool) {
	rc, ok := httpx.FunctionURLRequestContext(r.Context())
	if !ok || rc.Authorizer == nil || rc.Authorizer.IAM == nil {
		return "", false
	}
	return rc.Authorizer.IAM.UserARN, rc.Authorizer.IAM.UserARN != ""
}

// pathValue returns a path parameter, rejecting empty or oversized ones.
func pathValue(r *http.Request, name string) (string, error) {
	v := r.PathValue(name)
	if v == "" || len(v) > 256 {
		return "", errInvalid("invalid %s in path", name)
	}
	return v, nil
}
