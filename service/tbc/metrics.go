// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import "github.com/prometheus/client_golang/prometheus"

// blockMetrics counts block download activity.  The methods are safe
// on a nil receiver, so a server built without metrics needs no setup.
type blockMetrics struct {
	inserted  prometheus.Counter
	requested prometheus.Counter
	expired   *prometheus.CounterVec
}

func newBlockMetrics(namespace string) *blockMetrics {
	return &blockMetrics{
		inserted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "blocks_inserted_total",
			Help:      "The total number of blocks inserted",
		}),
		requested: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "block_requests_total",
			Help:      "The total number of block download requests",
		}),
		expired: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "block_requests_expired_total",
			Help: "The total number of block download requests that " +
				"expired, by result: dropped from blocks missing, " +
				"or retried and the peer closed",
		}, []string{"result"}),
	}
}

func (m *blockMetrics) blockInserted() {
	if m != nil {
		m.inserted.Inc()
	}
}

func (m *blockMetrics) blockRequested() {
	if m != nil {
		m.requested.Inc()
	}
}

func (m *blockMetrics) blockExpired(retried bool) {
	if m == nil {
		return
	}
	result := "dropped"
	if retried {
		result = "retried"
	}
	m.expired.WithLabelValues(result).Inc()
}
