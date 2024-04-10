// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build darwin

package tbc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

var (
	resources = []int{
		unix.RLIMIT_AS,
		unix.RLIMIT_MEMLOCK,
		unix.RLIMIT_NOFILE,
		unix.RLIMIT_NPROC,
	}
	resourceName = map[int]string{
		unix.RLIMIT_AS:      "memory",
		unix.RLIMIT_MEMLOCK: "lockedmem",
		unix.RLIMIT_NOFILE:  "nofiles",
		unix.RLIMIT_NPROC:   "processes",
	}
	resourceWant = map[int]unix.Rlimit{
		unix.RLIMIT_AS:      {Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY},
		unix.RLIMIT_MEMLOCK: {Cur: 775258112, Max: 775258112},
		unix.RLIMIT_NOFILE:  {Cur: 16384, Max: 16384},
		unix.RLIMIT_NPROC:   {Cur: 2666, Max: 2666},
	}
)

const ulimitSupported = true

func verifyUlimits() error {
	var p int
	for k, resource := range resources {
		var limit unix.Rlimit
		if err := unix.Getrlimit(resource, &limit); err != nil {
			return fmt.Errorf("ulimit %v: %w", k, err)
		}

		// Make sure it is a reasonable value
		limitRequired := resourceWant[resource]
		if limitRequired.Cur > limit.Cur || limitRequired.Max > limit.Max {
			return fmt.Errorf("ulimit %v: limit too low got %v, need %v",
				resourceName[resource], limit.Max, limitRequired.Max)
		}

		// Echo to user
		if err := unix.Getrlimit(resource, &limit); err != nil {
			return fmt.Errorf("ulimit %v: %w", k, err)
		}
		if p == 0 {
			log.Infof("%-16v  %-22v %-22v", "set resource", "current", "minumum")
			p++
		}
		log.Infof("%-16v: %-22v %-22v", resourceName[resource], limit.Cur,
			limitRequired.Max)
	}
	return nil
}
