// Command load drives a deployed LiteLogin environment at a fixed arrival
// rate and reports latency per step (ImplementationPlan.md, Phase 8, "Load
// testing").
//
// Two scenarios run together:
//
//   - login: the authorization code flow with PKCE, as a browser and a
//     public client would: GET /authorize, the login page, POST /login,
//     the redirect back through /authorize, and POST /token.
//   - refresh: refresh_token grants on a pool of token chains. Each chain
//     is one sign-in's refresh token, rotated on every use, so a chain
//     can only refresh once its previous refresh has returned; there are
//     enough chains that this doesn't limit the rate.
//
// Arrivals are open-loop: requests start on schedule whether or not
// earlier ones have finished, as real traffic does, so a slow server
// shows up as latency rather than as a lower rate. An arrival that finds
// no free chain, or too many requests in flight, is counted as skipped.
//
// The login host's rate-based WAF rules allow about 1 request per second
// per IP to the login and token endpoints, so the load generator's
// address must be exempt (rate_limit_exempt_cidrs in the environment's
// Terraform). See test/load/README.md.
//
//	go run ./test/load -issuer https://conformance.dev.litelogin.com \
//	  -client-id ... -users users.csv -login-rate 50 -refresh-rate 200 -duration 5m
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	issuer, clientID, redirectURI string
	users                         []user
	loginRate, refreshRate        float64
	duration, ramp                time.Duration
	chains, maxInFlight           int
	targets                       map[string]time.Duration
	maxErrorRate                  float64
	jsonOut                       string
}

type user struct{ email, password string }

func main() {
	var c config
	var usersFile, targets string
	flag.StringVar(&c.issuer, "issuer", "", "login host URL, e.g. https://login.example.com (required)")
	flag.StringVar(&c.clientID, "client-id", "", "a public client on the host, with the redirect URI and offline_access (required)")
	flag.StringVar(&c.redirectURI, "redirect-uri", "http://127.0.0.1/callback", "the client's redirect URI (never requested)")
	flag.StringVar(&usersFile, "users", "", "CSV of email,password for users in the client's pool (required)")
	flag.Float64Var(&c.loginRate, "login-rate", 50, "sign-ins started per second")
	flag.Float64Var(&c.refreshRate, "refresh-rate", 200, "refresh_token grants per second")
	flag.DurationVar(&c.duration, "duration", 5*time.Minute, "how long to hold the full rate")
	flag.DurationVar(&c.ramp, "ramp", time.Minute, "time to ramp up to the full rate first (not measured)")
	flag.IntVar(&c.chains, "chains", 0, "refresh token chains (default: 4 seconds' worth of refreshes)")
	flag.IntVar(&c.maxInFlight, "max-in-flight", 2000, "requests in flight before arrivals are skipped")
	flag.StringVar(&targets, "targets", "login_post=1s,token_code=500ms,token_refresh=500ms,authorize=500ms,login_page=500ms", "p99 latency target per step")
	flag.Float64Var(&c.maxErrorRate, "max-error-rate", 0.001, "highest error rate (errors per attempt) that passes")
	flag.StringVar(&c.jsonOut, "json", "", "also write the results to this file as JSON")
	flag.Parse()

	if c.issuer == "" || c.clientID == "" || usersFile == "" {
		flag.Usage()
		os.Exit(2)
	}
	c.issuer = strings.TrimSuffix(c.issuer, "/")
	var err error
	if c.users, err = readUsers(usersFile); err != nil {
		fatal(err)
	}
	if c.targets, err = parseTargets(targets); err != nil {
		fatal(err)
	}
	if c.chains == 0 {
		c.chains = max(int(c.refreshRate*4), 1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ok, err := run(ctx, c)
	if err != nil {
		fatal(err)
	}
	if !ok {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "load:", err)
	os.Exit(2)
}

func readUsers(path string) ([]user, error) {
	f, err := os.Open(path) //nolint:gosec // a path the operator gives
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var users []user
	for _, r := range rows {
		if len(r) < 2 || r[0] == "email" {
			continue
		}
		users = append(users, user{email: r[0], password: r[1]})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%s: no users", path)
	}
	return users, nil
}

func parseTargets(s string) (map[string]time.Duration, error) {
	t := map[string]time.Duration{}
	for _, kv := range strings.Split(s, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		d, err := time.ParseDuration(v)
		if !ok || err != nil {
			return nil, fmt.Errorf("bad target %q", kv)
		}
		t[k] = d
	}
	return t, nil
}

// ---- Statistics ----

type stats struct {
	mu        sync.Mutex
	measuring bool
	latency   map[string][]time.Duration
	errors    map[string]map[string]int
	skipped   map[string]int
}

func newStats() *stats {
	return &stats{latency: map[string][]time.Duration{}, errors: map[string]map[string]int{}, skipped: map[string]int{}}
}

func (s *stats) ok(step string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.measuring {
		s.latency[step] = append(s.latency[step], d)
	}
}

func (s *stats) fail(step string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.measuring {
		return
	}
	if s.errors[step] == nil {
		s.errors[step] = map[string]int{}
	}
	s.errors[step][errorKind(err)]++
}

func (s *stats) skip(scenario string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.measuring {
		s.skipped[scenario]++
	}
}

// errorKind keeps error counts low-cardinality: a status code or a short
// reason, without tokens or URLs.
func errorKind(err error) string {
	var se *statusError
	if errors.As(err, &se) {
		return fmt.Sprintf("HTTP %d%s", se.status, se.detail)
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout") {
		return "timeout"
	}
	msg := err.Error()
	if i := strings.Index(msg, ": "); i > 0 && i < 60 {
		msg = msg[:i]
	}
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}

type statusError struct {
	status int
	detail string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d%s", e.status, e.detail) }

// ---- Clients ----

var hiddenRE = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

type tester struct {
	c         config
	transport *http.Transport
	stats     *stats
	next      atomic.Uint64
	disco     struct {
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
	}
}

func (t *tester) client(jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport: t.transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func b64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// timed runs one step, recording its latency or error.
func (t *tester) timed(step string, fn func() error) error {
	start := time.Now()
	err := fn()
	if err != nil {
		t.stats.fail(step, err)
		return fmt.Errorf("%s: %w", step, err)
	}
	t.stats.ok(step, time.Since(start))
	return nil
}

// reply is a response that was read and closed.
type reply struct {
	location *url.URL // resolved against the request URL; nil if none
	body     string
}

// do sends req and checks the status is want (any redirect, if want is
// one).
func do(c *http.Client, req *http.Request, want int) (reply, error) {
	resp, err := c.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return reply{}, err
	}
	r := reply{body: string(body)}
	if loc, err := resp.Location(); err == nil {
		r.location = loc
	}
	redirect := func(code int) bool { return code >= 300 && code < 400 }
	if resp.StatusCode != want && (!redirect(want) || !redirect(resp.StatusCode)) {
		detail := ""
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			detail = " " + e.Error
		}
		return r, &statusError{status: resp.StatusCode, detail: detail}
	}
	if redirect(want) && r.location == nil {
		return r, errors.New("redirect without a location")
	}
	return r, nil
}

func (t *tester) form(ctx context.Context, u string, v url.Values) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", t.c.issuer)
	req.Header.Set("User-Agent", "LiteLogin-Load/1")
	return req
}

func (t *tester) get(ctx context.Context, u string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "LiteLogin-Load/1")
	return req
}

// login signs in as the next user and returns the tokens.
func (t *tester) login(ctx context.Context) (*tokens, error) {
	u := t.c.users[t.next.Add(1)%uint64(len(t.c.users))]
	jar, _ := cookiejar.New(nil)
	c := t.client(jar)

	verifier := b64(32)
	sum := sha256.Sum256([]byte(verifier))
	state := b64(12)
	q := url.Values{
		"response_type": {"code"}, "client_id": {t.c.clientID}, "redirect_uri": {t.c.redirectURI},
		"scope": {"openid email offline_access"}, "state": {state}, "nonce": {b64(12)}, "prompt": {"login"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}

	var loginURL string
	if err := t.timed("authorize", func() error {
		r, err := do(c, t.get(ctx, t.disco.Authorization+"?"+q.Encode()), http.StatusSeeOther)
		if err != nil {
			return err
		}
		loginURL = r.location.String()
		return nil
	}); err != nil {
		return nil, err
	}

	var page string
	if err := t.timed("login_page", func() error {
		r, err := do(c, t.get(ctx, loginURL), http.StatusOK)
		page = r.body
		return err
	}); err != nil {
		return nil, err
	}
	fields := url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(page, -1) {
		fields.Set(m[1], html.UnescapeString(m[2]))
	}
	fields.Set("email", u.email)
	fields.Set("password", u.password)

	var next string
	if err := t.timed("login_post", func() error {
		r, err := do(c, t.form(ctx, t.c.issuer+"/login", fields), http.StatusSeeOther)
		if err != nil {
			return err
		}
		loc := r.location
		if !strings.HasPrefix(loc.Path, "/authorize") {
			return fmt.Errorf("redirected to %s, not /authorize", loc.Path)
		}
		next = loc.String()
		return nil
	}); err != nil {
		return nil, err
	}

	var code string
	if err := t.timed("authorize_return", func() error {
		r, err := do(c, t.get(ctx, next), http.StatusSeeOther)
		if err != nil {
			return err
		}
		loc := r.location
		if !strings.HasPrefix(loc.String(), t.c.redirectURI) {
			return fmt.Errorf("redirected to %s, not the client", loc.Path)
		}
		if e := loc.Query().Get("error"); e != "" {
			return fmt.Errorf("authorization error %s", e)
		}
		if loc.Query().Get("state") != state {
			return errors.New("state mismatch")
		}
		code = loc.Query().Get("code")
		return nil
	}); err != nil {
		return nil, err
	}

	var tok tokens
	err := t.timed("token_code", func() error {
		r, err := do(c, t.form(ctx, t.disco.Token, url.Values{
			"grant_type": {"authorization_code"}, "client_id": {t.c.clientID}, "code": {code},
			"redirect_uri": {t.c.redirectURI}, "code_verifier": {verifier},
		}), http.StatusOK)
		if err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(r.body), &tok); err != nil {
			return err
		}
		if tok.RefreshToken == "" || tok.IDToken == "" {
			return errors.New("missing tokens")
		}
		return nil
	})
	return &tok, err
}

// refresh rotates a chain's refresh token, returning the new one.
func (t *tester) refresh(ctx context.Context, rt string) (string, error) {
	var tok tokens
	err := t.timed("token_refresh", func() error {
		r, err := do(t.client(nil), t.form(ctx, t.disco.Token, url.Values{
			"grant_type": {"refresh_token"}, "client_id": {t.c.clientID}, "refresh_token": {rt},
		}), http.StatusOK)
		if err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(r.body), &tok); err != nil {
			return err
		}
		if tok.RefreshToken == "" {
			return errors.New("no refresh token")
		}
		return nil
	})
	return tok.RefreshToken, err
}

// ---- Run ----

func run(ctx context.Context, c config) (bool, error) {
	t := &tester{
		c:     c,
		stats: newStats(),
		transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        c.maxInFlight,
			MaxIdleConnsPerHost: c.maxInFlight,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
	r, err := do(t.client(nil), t.get(ctx, c.issuer+"/.well-known/openid-configuration"), http.StatusOK)
	if err != nil {
		return false, fmt.Errorf("discovery: %w", err)
	}
	if err := json.Unmarshal([]byte(r.body), &t.disco); err != nil {
		return false, fmt.Errorf("discovery: %w", err)
	}

	// One sign-in first, so a misconfiguration fails fast and clearly.
	if _, err := t.login(ctx); err != nil {
		return false, fmt.Errorf("first sign-in: %w", err)
	}

	// Refresh chains, from sign-ins at the login rate (so seeding doesn't
	// exceed the load being tested).
	chains := make(chan string, c.chains)
	if c.refreshRate > 0 {
		fmt.Printf("seeding %d refresh token chains at %.0f sign-ins/s\n", c.chains, c.loginRate)
		if err := seed(ctx, t, chains, c.chains, max(c.loginRate, 10)); err != nil {
			return false, err
		}
	}

	var inFlight atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	total := c.ramp + c.duration
	fmt.Printf("ramping up for %s, then measuring for %s\n", c.ramp, c.duration)

	arrive := func(rate float64, name string, fn func()) {
		defer wg.Done()
		if rate <= 0 {
			return
		}
		var due float64 // arrivals due so far
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		started := 0
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				el := now.Sub(start)
				if el >= total {
					return
				}
				// Linear ramp: the rate grows from 0 over c.ramp.
				if c.ramp > 0 && el < c.ramp {
					due = rate * el.Seconds() * el.Seconds() / (2 * c.ramp.Seconds())
				} else {
					due = rate*c.ramp.Seconds()/2 + rate*(el-c.ramp).Seconds()
				}
				for ; started < int(due); started++ {
					if inFlight.Load() >= int64(c.maxInFlight) {
						t.stats.skip(name)
						continue
					}
					inFlight.Add(1)
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer inFlight.Add(-1)
						fn()
					}()
				}
			}
		}
	}

	wg.Add(3)
	go arrive(c.loginRate, "login", func() { _, _ = t.login(ctx) })
	go arrive(c.refreshRate, "refresh", func() {
		var rt string
		select {
		case rt = <-chains:
		default:
			t.stats.skip("refresh")
			return
		}
		next, err := t.refresh(ctx, rt)
		if err != nil {
			// A failed rotation may have spent the token; start a new
			// chain so the pool doesn't shrink.
			tok, lerr := t.login(ctx)
			if lerr != nil {
				return
			}
			next = tok.RefreshToken
		}
		chains <- next
	})
	go func() {
		defer wg.Done()
		measure := time.NewTimer(c.ramp)
		defer measure.Stop()
		progress := time.NewTicker(10 * time.Second)
		defer progress.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-measure.C:
				t.stats.mu.Lock()
				t.stats.measuring = true
				t.stats.mu.Unlock()
				fmt.Println("measuring")
			case now := <-progress.C:
				if now.Sub(start) >= total {
					return
				}
				t.stats.mu.Lock()
				fmt.Printf("%4.0fs  in flight %d  logins %d  refreshes %d  errors %d\n", now.Sub(start).Seconds(),
					inFlight.Load(), len(t.stats.latency["token_code"]), len(t.stats.latency["token_refresh"]), countErrors(t.stats))
				t.stats.mu.Unlock()
			}
		}
	}()
	wg.Wait()
	return report(t.stats, c), nil
}

func seed(ctx context.Context, t *tester, chains chan string, n int, rate float64) error {
	var wg sync.WaitGroup
	var made, failed atomic.Int64
	tick := time.NewTicker(time.Duration(float64(time.Second) / rate))
	defer tick.Stop()
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := t.login(ctx)
			if err != nil {
				failed.Add(1)
				return
			}
			made.Add(1)
			chains <- tok.RefreshToken
		}()
	}
	wg.Wait()
	if made.Load() < int64(n)/2 {
		return fmt.Errorf("seeding: only %d of %d sign-ins succeeded", made.Load(), n)
	}
	fmt.Printf("seeded %d chains (%d sign-ins failed)\n", made.Load(), failed.Load())
	return nil
}

func countErrors(s *stats) int {
	n := 0
	for _, m := range s.errors {
		for _, c := range m {
			n += c
		}
	}
	return n
}

type stepResult struct {
	Step      string         `json:"step"`
	Count     int            `json:"count"`
	PerSecond float64        `json:"per_second"`
	P50Ms     float64        `json:"p50_ms"`
	P90Ms     float64        `json:"p90_ms"`
	P99Ms     float64        `json:"p99_ms"`
	MaxMs     float64        `json:"max_ms"`
	TargetMs  float64        `json:"p99_target_ms,omitempty"`
	Errors    map[string]int `json:"errors,omitempty"`
	ErrorRate float64        `json:"error_rate"`
	Pass      bool           `json:"pass"`
}

var stepOrder = []string{"authorize", "login_page", "login_post", "authorize_return", "token_code", "token_refresh"}

func report(s *stats, c config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	pct := func(ds []time.Duration, p float64) time.Duration {
		if len(ds) == 0 {
			return 0
		}
		return ds[min(int(p*float64(len(ds))), len(ds)-1)]
	}

	pass := true
	var results []stepResult
	fmt.Printf("\n%-17s %8s %7s %8s %8s %8s %8s %8s  %s\n", "step", "count", "/s", "p50", "p90", "p99", "max", "target", "errors")
	for _, step := range stepOrder {
		ds := s.latency[step]
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		errs := 0
		for _, n := range s.errors[step] {
			errs += n
		}
		r := stepResult{
			Step: step, Count: len(ds), PerSecond: float64(len(ds)) / c.duration.Seconds(),
			P50Ms: ms(pct(ds, .5)), P90Ms: ms(pct(ds, .9)), P99Ms: ms(pct(ds, .99)), Errors: s.errors[step], Pass: true,
		}
		if len(ds) > 0 {
			r.MaxMs = ms(ds[len(ds)-1])
		}
		if attempts := len(ds) + errs; attempts > 0 {
			r.ErrorRate = float64(errs) / float64(attempts)
		}
		target := "-"
		if d, ok := c.targets[step]; ok {
			r.TargetMs = ms(d)
			target = d.String()
			if pct(ds, .99) > d {
				r.Pass = false
			}
		}
		if r.ErrorRate > c.maxErrorRate || (len(ds) == 0 && errs > 0) {
			r.Pass = false
		}
		pass = pass && r.Pass
		var errText []string
		for k, n := range s.errors[step] {
			errText = append(errText, fmt.Sprintf("%s ×%d", k, n))
		}
		sort.Strings(errText)
		mark := ""
		if !r.Pass {
			mark = "  FAIL"
		}
		fmt.Printf("%-17s %8d %7.1f %7.0fms %7.0fms %7.0fms %7.0fms %8s  %s%s\n", step, r.Count, r.PerSecond, r.P50Ms, r.P90Ms, r.P99Ms, r.MaxMs, target, strings.Join(errText, ", "), mark)
		results = append(results, r)
	}
	for name, n := range s.skipped {
		fmt.Printf("skipped %s arrivals: %d (no free chain, or -max-in-flight reached)\n", name, n)
		if n > 0 {
			pass = false
		}
	}
	logins := float64(len(s.latency["token_code"])) / c.duration.Seconds()
	refreshes := float64(len(s.latency["token_refresh"])) / c.duration.Seconds()
	fmt.Printf("\nachieved: %.1f sign-ins/s (target %g), %.1f refreshes/s (target %g)\n", logins, c.loginRate, refreshes, c.refreshRate)
	if logins < 0.95*c.loginRate || refreshes < 0.95*c.refreshRate {
		pass = false
	}
	if pass {
		fmt.Println("PASS")
	} else {
		fmt.Println("FAIL")
	}

	if c.jsonOut != "" {
		out, _ := json.MarshalIndent(map[string]any{
			"issuer": c.issuer, "login_rate": c.loginRate, "refresh_rate": c.refreshRate,
			"duration_s": c.duration.Seconds(), "steps": results, "skipped": s.skipped,
			"achieved_logins_per_s": logins, "achieved_refreshes_per_s": refreshes, "pass": pass,
		}, "", "  ")
		if err := os.WriteFile(c.jsonOut, out, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "load:", err)
		}
	}
	return pass
}
