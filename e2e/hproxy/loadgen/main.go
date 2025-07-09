package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	concurrency = flag.Int("c", 100, "concurrent workers")
	duration    = flag.Duration("d", 10*time.Second, "test duration")
	url         = flag.String("url", "http://localhost:8545", "target URL")
)

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

func main() {
	flag.Parse()

	var totalSent, totalOK, totalFail atomic.Int64
	var wg sync.WaitGroup

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	body := mustMarshal(jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_blockNumber",
		Params:  []any{},
		ID:      1,
	})
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: *concurrency,
			DisableKeepAlives:   false,
		},
		Timeout: 5 * time.Second,
	}

	// Pre-allocate per-worker latency slices
	latencyBuckets := make([][]time.Duration, *concurrency)
	for i := range latencyBuckets {
		latencyBuckets[i] = make([]time.Duration, 0, 200000)
	}

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localLatencies := latencyBuckets[workerID]

			for {
				select {
				case <-ctx.Done():
					latencyBuckets[workerID] = localLatencies
					return
				default:
					start := time.Now()
					totalSent.Add(1)

					resp, err := client.Post(*url, "application/json", bytes.NewReader(body))
					lat := time.Since(start)
					localLatencies = append(localLatencies, lat)
					if err != nil {
						totalFail.Add(1)
						continue
					}

					if resp.StatusCode == http.StatusOK {
						totalOK.Add(1)
					} else {
						totalFail.Add(1)
					}

					// Read body
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}
		}(i)
	}

	start := time.Now()
	select {
	case <-ctx.Done():
	case <-time.After(*duration):
		cancel()
	}
	wg.Wait()

	secs := time.Since(start).Seconds()

	fmt.Printf("Duration:    %.1fs\n", secs)
	fmt.Printf("Concurrency: %d\n", *concurrency)
	fmt.Printf("Total Sent:  %d\n", totalSent.Load())
	fmt.Printf("Successful:  %d\n", totalOK.Load())
	fmt.Printf("Failed:      %d\n", totalFail.Load())
	fmt.Printf("Actual RPS:  %.1f\n", float64(totalSent.Load())/secs)

	// Latencies
	// Aggregate latencies from all workers
	var allLatencies []time.Duration
	for _, bucket := range latencyBuckets {
		allLatencies = append(allLatencies, bucket...)
	}

	summary := summarizeLatency(allLatencies)
	fmt.Printf("Latency min: %v\n", summary.min)
	fmt.Printf("Latency max: %v\n", summary.max)
	fmt.Printf("Latency avg: %v\n", summary.avg)
	fmt.Printf("Latency p50: %v\n", summary.p50)
	fmt.Printf("Latency p90: %v\n", summary.p90)
	fmt.Printf("Latency p95: %v\n", summary.p95)
	fmt.Printf("Latency p99: %v\n", summary.p99)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

type latencySummary struct {
	min, max, avg      time.Duration
	p50, p90, p95, p99 time.Duration
}

func summarizeLatency(latencies []time.Duration) latencySummary {
	if len(latencies) == 0 {
		return latencySummary{}
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	var total time.Duration
	for _, l := range latencies {
		total += l
	}

	// Percentile
	p := func(p float64) time.Duration {
		idx := int(float64(len(latencies))*p + 0.5)
		if idx >= len(latencies) {
			idx = len(latencies) - 1
		}
		return latencies[idx]
	}

	return latencySummary{
		min: latencies[0],
		max: latencies[len(latencies)-1],
		avg: total / time.Duration(len(latencies)),
		p50: p(0.50),
		p90: p(0.90),
		p95: p(0.95),
		p99: p(0.99),
	}
}
