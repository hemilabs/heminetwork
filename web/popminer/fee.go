// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"time"
)

const mempoolRecommendedFees = "/api/v1/fees/recommended"

// recommendedFees is the result from the mempool.space API.
type recommendedFees struct {
	FastestFee  uint `json:"fastestFee"`
	HalfHourFee uint `json:"halfHourFee"`
	HourFee     uint `json:"hourFee"`
	EconomyFee  uint `json:"economyFee"`
	MinimumFee  uint `json:"minimumFee"`
}

// pick returns the recommended fee value for the specified type.
func (r recommendedFees) pick(f RecommendedFeeType) uint {
	switch f {
	case RecommendedFeeTypeFastest:
		return r.FastestFee
	case RecommendedFeeTypeHalfHour:
		return r.HalfHourFee
	case RecommendedFeeTypeHour:
		return r.HourFee
	case RecommendedFeeTypeEconomy:
		return r.EconomyFee
	case RecommendedFeeTypeMinimum:
		return r.MinimumFee
	default:
		panic("bug: unknown recommended fee type")
	}
}

// automaticFees runs a loop to refresh the fee used by the PoP Miner using
// the recommended fee of the specified type from the mempool.space REST API.
func (m *Miner) automaticFees(fee RecommendedFeeType, multiplier float64, refresh time.Duration) {
	log.Tracef("automaticFees")
	defer log.Tracef("automaticFees exit")
	defer m.wg.Done()

	if m.mempoolSpaceURL == "" {
		// Not supported for this network.
		return
	}

	for {
		m.updateFee(m.ctx, fee, multiplier)

		select {
		case <-m.ctx.Done():
			return
		case <-time.After(refresh):
		}
	}
}

// updateFee requests the recommended fees from mempool.space and updates the
// fee being used by the PoP Miner.
func (m *Miner) updateFee(ctx context.Context, fee RecommendedFeeType, multiplier float64) {
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	// Retrieve recommended fees from mempool.space.
	fees, err := m.getRecommendedFees(ctx)
	if err != nil {
		log.Warningf("Failed to fetch recommended fees: %v", err)
		return
	}

	// Apply multiplier.
	recommendedFee := fees.pick(fee)
	multipliedFee := math.Ceil(float64(recommendedFee) * multiplier)

	// Bounds check before converting to uint32.
	switch {
	case multipliedFee < 1:
		multipliedFee = 1
	case multipliedFee > 1<<32-1:
		multipliedFee = 1<<32 - 1
	}

	log.Debugf("Updating PoP miner fee (%d * %f): %d sats/vB",
		recommendedFee, multiplier, uint64(multipliedFee))

	// Update fee used by the miner.
	m.SetFee(uint(multipliedFee))
}

// getRecommendedFees requests the recommended fees from the mempool.space
// REST API.
func (m *Miner) getRecommendedFees(ctx context.Context) (*recommendedFees, error) {
	log.Debugf("Requesting recommended fees from mempool.space...")

	// Join API path.
	apiPath, err := url.JoinPath(m.mempoolSpaceURL, mempoolRecommendedFees)
	if err != nil {
		return nil, fmt.Errorf("join mempool.space URL path: %w", err)
	}

	// Create HTTP GET request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("create recommended fees request: %w", err)
	}
	req.Header.Add("Accept", "application/json")

	// Make HTTP request.
	res, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request recommended fees: %w", err)
	}
	defer res.Body.Close()

	// Make sure status code is 200.
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request recommended fees: %s", res.Status)
	}

	// Decode response.
	var fees recommendedFees
	if err = json.NewDecoder(res.Body).Decode(&fees); err != nil {
		return nil, fmt.Errorf("decode recommended fees response: %w", err)
	}
	return &fees, nil
}
