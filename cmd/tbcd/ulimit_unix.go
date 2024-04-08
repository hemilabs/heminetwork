// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build unix && !windows

package main

import (
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

var resources = []int{
	unix.RLIMIT_AS,
	unix.RLIMIT_MEMLOCK,
	unix.RLIMIT_NOFILE,
	unix.RLIMIT_NPROC,
	unix.RLIMIT_RSS,
}

func nameForResource(id int) string {
	switch id {
	case unix.RLIMIT_AS: // unix.RLIMIT_RSS these have the same value of 5
		return "memory,rss"
	case unix.RLIMIT_MEMLOCK:
		return "lockedmem"
	case unix.RLIMIT_NOFILE:
		return "nofiles"
	case unix.RLIMIT_NPROC:
		return "processes"
	}

	return "unknown"
}

func wantForResource(id int) unix.Rlimit {
	switch id {
	case unix.RLIMIT_AS: // unix.RLIMIT_RSS these have the same value of 5
		return unix.Rlimit{Cur: math.MaxUint64, Max: math.MaxUint64}
	case unix.RLIMIT_MEMLOCK:
		return unix.Rlimit{Cur: 775258112, Max: 775258112}
	case unix.RLIMIT_NOFILE:
		return unix.Rlimit{Cur: 16384, Max: 16384}
	case unix.RLIMIT_NPROC:
		return unix.Rlimit{Cur: 4196, Max: 4196}
	}

	panic(fmt.Sprintf("unsupported resource: %d", id))
}

func setUlimits() error {
	var p int
	for k, resource := range resources {
		var limit unix.Rlimit
		if err := unix.Getrlimit(resource, &limit); err != nil {
			return fmt.Errorf("ulimit %v: %w", k, err)
		}
		// Set to Max
		l := unix.Rlimit{Cur: limit.Max, Max: limit.Max}
		if err := unix.Setrlimit(resource, &l); err != nil {
			return fmt.Errorf("set ulimit %v: %v",
				nameForResource(resource), err)
		}

		// Make sure it is a reasonable value
		limitRequired := wantForResource(resource)
		if limitRequired.Cur > limit.Cur || limitRequired.Max > limit.Max {
			return fmt.Errorf("set ulimit %v: limit too low got %v, need %v",
				nameForResource(resource), limit.Max, limitRequired.Max)
		}

		// Echo to user
		if err := unix.Getrlimit(resource, &limit); err != nil {
			return fmt.Errorf("ulimit %v: %w", k, err)
		}
		if p == 0 {
			log.Infof("%-16v  %-22v %-22v", "set resource", "current", "minumum")
			p++
		}
		log.Infof("%-16v: %-22v %-22v", nameForResource(resource), limit.Cur,
			limitRequired.Max)
	}
	return nil
}
