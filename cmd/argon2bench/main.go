// Command argon2bench measures argon2id password verification inside
// Lambda, to choose the Auth Lambda's memory size (Lambda CPU scales with
// memory). scripts/bench-argon2.sh deploys it temporarily, invokes it at
// several memory sizes and deletes it. It's not part of any environment.
package main

import (
	"context"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/litelogin/litelogin/internal/crypto"
)

// Request sets the run size.
type Request struct {
	Iterations  int `json:"iterations"`  // sequential verifications (default 20)
	Concurrency int `json:"concurrency"` // parallel verifications per round (default 1)
}

// Result reports verification latency in milliseconds.
type Result struct {
	MemoryMB    int     `json:"memory_mb"`
	CPUs        int     `json:"cpus"`
	Params      string  `json:"params"`
	Iterations  int     `json:"iterations"`
	Concurrency int     `json:"concurrency"`
	P50         float64 `json:"p50_ms"`
	P90         float64 `json:"p90_ms"`
	Max         float64 `json:"max_ms"`
}

func handle(_ context.Context, req Request) (*Result, error) {
	if req.Iterations <= 0 {
		req.Iterations = 20
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 1
	}
	p := crypto.DefaultArgon2Params
	h := crypto.NewPasswordHasher(p)
	encoded, err := h.Hash("benchmark password")
	if err != nil {
		return nil, err
	}
	for range 2 { // warm up
		_, _, _ = h.Verify("benchmark password", encoded)
	}

	var mu sync.Mutex
	var samples []float64
	for range req.Iterations {
		var wg sync.WaitGroup
		for range req.Concurrency {
			wg.Go(func() {
				start := time.Now()
				_, _, _ = h.Verify("benchmark password", encoded)
				ms := float64(time.Since(start).Microseconds()) / 1000
				mu.Lock()
				samples = append(samples, ms)
				mu.Unlock()
			})
		}
		wg.Wait()
	}
	slices.Sort(samples)
	at := func(q float64) float64 { return samples[int(q*float64(len(samples)-1))] }
	mem, _ := strconv.Atoi(os.Getenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE"))
	return &Result{
		MemoryMB: mem, CPUs: runtime.NumCPU(), Iterations: req.Iterations, Concurrency: req.Concurrency,
		Params: "m=" + strconv.Itoa(int(p.MemoryKiB)) + ",t=" + strconv.Itoa(int(p.Time)) + ",p=" + strconv.Itoa(int(p.Threads)),
		P50:    at(0.5), P90: at(0.9), Max: samples[len(samples)-1],
	}, nil
}

func main() {
	lambda.Start(handle)
}
