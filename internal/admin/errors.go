package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/litelogin/litelogin/internal/store"
)

// Error is a request that can't be done as asked. In the Admin API it's
// the error response: {"error": code, "message": text}.
type Error struct {
	// Status is the HTTP status that fits the error.
	Status int `json:"-"`
	// Code is a stable identifier, such as invalid_request.
	Code string `json:"error"`
	// Message says what's wrong and how to fix it, for people.
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

func errInvalid(format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: fmt.Sprintf(format, args...)}
}

func errNotFound(msg string) *Error {
	return &Error{Status: http.StatusNotFound, Code: "not_found", Message: msg}
}

func errConflict(code, msg string) *Error {
	return &Error{Status: http.StatusConflict, Code: code, Message: msg}
}

func errNotImplemented(code, msg string) *Error {
	return &Error{Status: http.StatusNotImplemented, Code: code, Message: msg}
}

var errNoHost = errNotFound("no such login host")

// AsError maps any error a Service method returns to an *Error. Anything
// not recognized is a 500 whose details callers should log, not show.
func AsError(err error) *Error {
	var ae *Error
	if errors.As(err, &ae) {
		return ae
	}
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		return &Error{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "request body is too large"}
	case errors.Is(err, store.ErrNotFound):
		return errNotFound(strings.TrimPrefix(err.Error(), "store: "))
	case errors.Is(err, store.ErrAlreadyExists):
		return errConflict("already_exists", "the resource already exists")
	case errors.Is(err, store.ErrEmailTaken):
		return errConflict("email_taken", "a user in this pool already has this email")
	case errors.Is(err, store.ErrHostTaken):
		return errConflict("host_taken", "this login host already exists")
	case errors.Is(err, store.ErrVersionMismatch):
		return &Error{Status: http.StatusPreconditionFailed, Code: "version_mismatch",
			Message: "the resource was changed since it was read; get it again and retry"}
	case errors.Is(err, store.ErrPoolNotActive):
		return errConflict("pool_not_active", "the pool doesn't exist in this org, or is being deleted")
	case errors.Is(err, store.ErrPoolInUse):
		return errConflict("pool_in_use", "a client or login host still uses this pool")
	case errors.Is(err, store.ErrWrongPool):
		return errConflict("wrong_pool", "a client can only be on login hosts of its own org and user pool")
	case errors.Is(err, store.ErrHostInUse):
		return errConflict("host_in_use", "clients are still on this login host: remove them first")
	case errors.Is(err, store.ErrLastHost):
		return errConflict("last_host", "this is the client's only login host; every client is on at least one")
	case errors.Is(err, store.ErrDefaultHost):
		return errConflict("default_host", "an org's default login host can't be removed")
	case errors.Is(err, store.ErrIDPInUse):
		return errConflict("idp_in_use", "a login host still shows this identity provider: remove it from the host's idps first")
	case errors.Is(err, store.ErrIDPNotFound):
		return errInvalid("idps: every identity provider must exist in the host's user pool")
	case errors.Is(err, store.ErrTooMany):
		return errConflict("limit_reached", "the limit for this resource has been reached")
	case errors.Is(err, store.ErrConditionFailed):
		return errConflict("conflict", "the resource isn't in a state that allows this; get it again and retry")
	case errors.Is(err, store.ErrInvalidEmail):
		return errInvalid("invalid email address")
	case errors.Is(err, store.ErrInvalidHost):
		return errInvalid("invalid host name")
	}
	return &Error{Status: http.StatusInternalServerError, Code: "internal_error", Message: "internal error"}
}
