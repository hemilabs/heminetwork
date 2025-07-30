// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.
package popm

// Prometheus makes kitty cry. Hide it in here.

import "github.com/prometheus/client_golang/prometheus"

type valueVecFunc[T prometheus.Collector] struct {
	metric T
	fn     func(t T)
}

func newValueVecFunc[T prometheus.Collector](metric T, fn func(t T)) prometheus.Collector {
	return &valueVecFunc[T]{metric: metric, fn: fn}
}

func (v *valueVecFunc[T]) Describe(descs chan<- *prometheus.Desc) {
	v.metric.Describe(descs)
}

func (v *valueVecFunc[T]) Collect(metrics chan<- prometheus.Metric) {
	v.fn(v.metric)
	v.metric.Collect(metrics)
}
