package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"

	"github.com/litelogin/litelogin/internal/configcache"
)

// capacity adds up the capacity DynamoDB reports consuming, per table.
type capacity struct {
	mu          sync.Mutex
	read, write map[string]float64
	calls       map[string]int
}

func newCapacity() *capacity {
	return &capacity{read: map[string]float64{}, write: map[string]float64{}, calls: map[string]int{}}
}

func (c *capacity) add(op string, list ...types.ConsumedCapacity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls[op]++
	for _, cc := range list {
		table := "?"
		if cc.TableName != nil {
			table = *cc.TableName
		}
		r, w := 0.0, 0.0
		if cc.ReadCapacityUnits != nil {
			r = *cc.ReadCapacityUnits
		}
		if cc.WriteCapacityUnits != nil {
			w = *cc.WriteCapacityUnits
		}
		if r == 0 && w == 0 && cc.CapacityUnits != nil {
			// Only the total: reads and writes are told apart by the
			// operation.
			if strings.HasPrefix(op, "Get") || op == "Query" || op == "Scan" || op == "BatchGetItem" || op == "TransactGetItems" {
				r = *cc.CapacityUnits
			} else {
				w = *cc.CapacityUnits
			}
		}
		c.read[table] += r
		c.write[table] += w
	}
}

// snapshot returns the totals so far and resets them.
func (c *capacity) snapshot() (read, write map[string]float64, calls map[string]int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	read, write, calls = c.read, c.write, c.calls
	c.read, c.write, c.calls = map[string]float64{}, map[string]float64{}, map[string]int{}
	return read, write, calls
}

// middleware asks every request for its consumed capacity and records it.
func (c *capacity) middleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("MeasureCapacity",
		func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
			const rc = types.ReturnConsumedCapacityIndexes
			switch p := in.Parameters.(type) {
			case *dynamodb.GetItemInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.PutItemInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.UpdateItemInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.DeleteItemInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.QueryInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.ScanInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.BatchGetItemInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.BatchWriteItemInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.TransactGetItemsInput:
				p.ReturnConsumedCapacity = rc
			case *dynamodb.TransactWriteItemsInput:
				p.ReturnConsumedCapacity = rc
			}
			out, md, err := next.HandleInitialize(ctx, in)
			if err != nil {
				return out, md, err
			}
			op := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%T", out.Result), "*dynamodb."), "Output")
			switch o := out.Result.(type) {
			case *dynamodb.GetItemOutput:
				c.add(op, deref(o.ConsumedCapacity)...)
			case *dynamodb.PutItemOutput:
				c.add(op, deref(o.ConsumedCapacity)...)
			case *dynamodb.UpdateItemOutput:
				c.add(op, deref(o.ConsumedCapacity)...)
			case *dynamodb.DeleteItemOutput:
				c.add(op, deref(o.ConsumedCapacity)...)
			case *dynamodb.QueryOutput:
				c.add(op, deref(o.ConsumedCapacity)...)
			case *dynamodb.ScanOutput:
				c.add(op, deref(o.ConsumedCapacity)...)
			case *dynamodb.BatchGetItemOutput:
				c.add(op, o.ConsumedCapacity...)
			case *dynamodb.BatchWriteItemOutput:
				c.add(op, o.ConsumedCapacity...)
			case *dynamodb.TransactGetItemsOutput:
				c.add(op, o.ConsumedCapacity...)
			case *dynamodb.TransactWriteItemsOutput:
				c.add(op, o.ConsumedCapacity...)
			}
			return out, md, err
		}), middleware.After)
}

func deref(c *types.ConsumedCapacity) []types.ConsumedCapacity {
	if c == nil {
		return nil
	}
	return []types.ConsumedCapacity{*c}
}

// TestRequestCosts measures the work behind each request of a sign-in and
// a refresh, for Cost.md: DynamoDB request units (the consumed capacity
// DynamoDB Local reports, indexes included), KMS Sign calls, emails and
// response body sizes. It logs a table per case; run it with -v.
func TestRequestCosts(t *testing.T) {
	for _, cached := range []bool{true, false} {
		name := "config cached"
		ttl := configcache.DefaultTTL
		if !cached {
			name, ttl = "config not cached", 0
		}
		t.Run(name, func(t *testing.T) {
			c := newCapacity()
			e := newEnvWith(t, false, envOptions{
				db:        func(o *dynamodb.Options) { o.APIOptions = append(o.APIOptions, c.middleware) },
				configTTL: ttl,
			})
			e.newUser()
			b := e.browser()
			// Warm the cache (and sign in once), so the measured sign-in
			// is a returning user's on a warm instance.
			verifier, challenge := pkce()
			e.refreshToken(b)
			b = e.browser()
			c.snapshot()
			emails, signs := len(e.mail.Messages()), e.kms.SignCalls

			var rows []string
			size := 0 // the response body's bytes
			step := func(name string, f func()) {
				t.Helper()
				f()
				read, write, calls := c.snapshot()
				var ops []string
				for op, n := range calls {
					ops = append(ops, fmt.Sprintf("%s×%d", op, n))
				}
				sort.Strings(ops)
				rows = append(rows, fmt.Sprintf("| %s | %s | %s | %d | %d | %d | %s |", name,
					units(read), units(write), e.kms.SignCalls-signs, len(e.mail.Messages())-emails, size, strings.Join(ops, ", ")))
				emails, signs = len(e.mail.Messages()), e.kms.SignCalls
			}

			q := e.authzQuery(challenge)
			var p page
			step("authorize", func() { p = b.get("/authorize?" + q.Encode()); size = len(p.body) })
			login := p.location
			step("login_page", func() { p = b.get(login); size = len(p.body) })
			authz := hiddenRE.FindAllStringSubmatch(p.body, -1)
			form := creds("alice@example.com", password)
			for _, m := range authz {
				form.Set(m[1], html.UnescapeString(m[2]))
			}
			step("login_post", func() { p = b.do(http.MethodPost, "/login", form); size = len(p.body) })
			back := p.location
			step("authorize_return", func() { p = b.get(back); size = len(p.body) })
			loc, err := url.Parse(p.location)
			if err != nil || loc.Query().Get("code") == "" {
				t.Fatalf("no code: %d %q", p.status, p.location)
			}
			var tok tokenResp
			step("token_code", func() { tok = e.exchange(loc.Query().Get("code"), verifier); size = jsonSize(tok.body) })
			if tok.status != http.StatusOK {
				t.Fatalf("exchange: %d %v", tok.status, tok.body)
			}
			step("token_refresh", func() { tok = e.refresh(tok.body["refresh_token"].(string)); size = jsonSize(tok.body) })
			if tok.status != http.StatusOK {
				t.Fatalf("refresh: %d %v", tok.status, tok.body)
			}
			t.Logf("%s\n| Step | Read units | Write units | KMS Sign | Emails | Body bytes | DynamoDB calls |\n| -- | -- | -- | -- | -- | -- | -- |\n%s",
				name, strings.Join(rows, "\n"))
		})
	}
}

func units(m map[string]float64) string {
	total := 0.0
	for _, v := range m {
		total += v
	}
	return fmt.Sprintf("%g", total)
}

func jsonSize(v any) int {
	b, _ := json.Marshal(v)
	return len(b)
}
