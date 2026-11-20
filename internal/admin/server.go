// Package admin is LiteLogin's management API. Service does each
// operation and checks the caller's permissions; Server is the Admin API,
// JSON over HTTP for deployment operators, served by the Admin Lambda's
// IAM-authenticated function URL (Architecture.md, "Admin API").
package admin

import (
	"context"
	"net/http"

	"github.com/litelogin/litelogin/internal/store"
)

// CallerFunc returns the IAM principal ARN of the request's caller, or
// false if the request isn't authenticated.
type CallerFunc func(*http.Request) (string, bool)

// Server is the Admin API: JSON over HTTP in front of a Service. Every
// caller is an operator (Principal.Operator).
type Server struct {
	Service *Service
	Caller  CallerFunc
}

// maxBodyBytes bounds request bodies.
const maxBodyBytes = 64 << 10

// Handler returns the API's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, h func(http.ResponseWriter, *http.Request) error) {
		mux.Handle(pattern, s.handle(h))
	}

	route("POST /v1/orgs", s.createOrg)
	route("GET /v1/orgs", s.listOrgs)
	route("GET /v1/orgs/{org}", s.getOrg)
	route("PATCH /v1/orgs/{org}", s.updateOrg)
	route("POST /v1/orgs/{org}/suspend", s.setOrgStatus(store.OrgSuspended))
	route("POST /v1/orgs/{org}/reactivate", s.setOrgStatus(store.OrgActive))

	route("POST /v1/orgs/{org}/pools", s.createPool)
	route("GET /v1/orgs/{org}/pools", s.listPools)
	route("GET /v1/pools/{pool}", s.getPool)
	route("PATCH /v1/pools/{pool}", s.updatePool)
	route("DELETE /v1/pools/{pool}", s.deletePool)
	route("POST /v1/pools/{pool}/idps", s.createIDP)
	route("GET /v1/pools/{pool}/idps", s.listIDPs)
	route("GET /v1/pools/{pool}/idps/{idp}", s.getIDP)
	route("PATCH /v1/pools/{pool}/idps/{idp}", s.updateIDP)
	route("DELETE /v1/pools/{pool}/idps/{idp}", s.deleteIDP)

	route("POST /v1/orgs/{org}/clients", s.createClient)
	route("GET /v1/orgs/{org}/clients", s.listClients)
	route("GET /v1/clients/{client}", s.getClient)
	route("PATCH /v1/clients/{client}", s.updateClient)
	route("DELETE /v1/clients/{client}", s.deleteClient)
	route("POST /v1/clients/{client}/disable", s.setClientStatus(store.ClientDisabled))
	route("POST /v1/clients/{client}/enable", s.setClientStatus(store.ClientActive))
	route("POST /v1/clients/{client}/secret", s.rotateClientSecret)

	route("GET /v1/clients/{client}/hosts", s.listClientHosts)

	route("GET /v1/orgs/{org}/hosts", s.listOrgHosts)
	route("POST /v1/orgs/{org}/hosts", s.addHost)
	route("GET /v1/hosts/{host}", s.getHost)
	route("PATCH /v1/hosts/{host}", s.updateHost)
	route("DELETE /v1/hosts/{host}", s.removeHost)
	route("GET /v1/hosts/{host}/clients", s.listHostClients)
	route("PUT /v1/hosts/{host}/clients/{client}", s.addHostClient)
	route("DELETE /v1/hosts/{host}/clients/{client}", s.removeHostClient)

	route("POST /v1/pools/{pool}/users", s.createUser)
	route("GET /v1/pools/{pool}/users", s.listUsers)
	route("GET /v1/users/{user}", s.getUser)
	route("PATCH /v1/users/{user}", s.updateUser)
	route("DELETE /v1/users/{user}", s.deleteUser)
	route("POST /v1/users/{user}/disable", s.disableUser)
	route("POST /v1/users/{user}/enable", s.enableUser)
	route("GET /v1/users/{user}/sessions", s.listSessions)
	route("DELETE /v1/users/{user}/sessions", s.revokeSessions)
	route("GET /v1/users/{user}/passkeys", s.listPasskeys)
	route("DELETE /v1/users/{user}/passkeys/{passkey}", s.deletePasskey)
	route("DELETE /v1/users/{user}/mfa", s.resetMFA)
	route("GET /v1/users/{user}/identities", s.listIdentities)
	route("DELETE /v1/users/{user}/identities/{idp}", s.unlinkIdentity)

	route("GET /v1/keys", s.listKeys)

	route("/", func(http.ResponseWriter, *http.Request) error {
		return errNotFound("no such endpoint: check the method and path")
	})

	return s.authenticate(mux)
}

type callerKey struct{}

func callerARN(ctx context.Context) string {
	arn, _ := ctx.Value(callerKey{}).(string)
	return arn
}

// principal is who a request acts for: its caller, an operator.
func principal(r *http.Request) Principal {
	return Principal{ID: callerARN(r.Context()), Operator: true}
}

// authenticate rejects requests without a caller. In Lambda the function
// URL has already verified the SigV4 signature; this is defense in depth
// against a misconfigured auth type.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arn, ok := s.Caller(r)
		if !ok || arn == "" {
			writeError(w, &Error{Status: http.StatusUnauthorized, Code: "unauthenticated",
				Message: "requests must be signed with AWS SigV4 by an IAM principal"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, arn)))
	})
}

// handle adapts a handler that returns an error, and adds the body limit,
// idempotency and audit logging around it.
func (s *Server) handle(h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		rec := &recorder{ResponseWriter: w}
		replayed := false
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			s.run(h, rec, r)
		} else {
			replayed = s.idempotent(h, rec, r)
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.audit(r, rec.status(), replayed)
		}
	})
}

// run calls h and writes its error, if any.
func (s *Server) run(h func(http.ResponseWriter, *http.Request) error, w *recorder, r *http.Request) {
	if err := h(w, r); err != nil {
		ae := AsError(err)
		if ae.Status >= 500 {
			s.Service.log().ErrorContext(r.Context(), "admin request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		}
		writeError(w, ae)
	}
}

// audit logs every request that can change data, with the caller's IAM
// principal (Architecture.md, "Audit logging").
func (s *Server) audit(r *http.Request, status int, replayed bool) {
	attrs := []any{
		"caller", callerARN(r.Context()), "method", r.Method, "path", r.URL.Path, "status", status,
	}
	if k := r.Header.Get("Idempotency-Key"); k != "" {
		attrs = append(attrs, "idempotency_key", k, "replayed", replayed)
	}
	if id := requestID(r); id != "" {
		attrs = append(attrs, "request_id", id)
	}
	s.Service.log().InfoContext(r.Context(), "admin audit", attrs...)
}
