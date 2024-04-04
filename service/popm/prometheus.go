// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build !js && !wasm

package popm

import (
	"context"
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/service/deucalion"
)

func (m *Miner) handlePrometheus(ctx context.Context) error {
	d, err := deucalion.New(&deucalion.Config{
		ListenAddress: m.cfg.PrometheusListenAddress,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	cs := []prometheus.Collector{
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Subsystem: promSubsystem,
			Name:      "running",
			Help:      "Is pop miner service running.",
		}, m.promRunning),
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := d.Run(ctx, cs); !errors.Is(err, context.Canceled) {
			log.Errorf("prometheus terminated with error: %v", err)
			return
		}
		log.Infof("prometheus clean shutdown")
	}()

	return nil
}
