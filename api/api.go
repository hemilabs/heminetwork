// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// hexDecode decodes a string that may be prefixed with " and/or 0x. Thus,
// "0x00" and 0x00 or 00 are all valid hex encodings. If length is provided the
// decoded size must exactly match. The length parameter will be ignored if it
// is less than 0.
func hexDecode(data []byte, length int) ([]byte, error) {
	x, _ := strings.CutPrefix(strings.Trim(string(data), "\""), "0x")
	s, err := hex.DecodeString(x)
	if err != nil {
		return nil, err
	}
	if length >= 0 && length != len(s) {
		return nil, fmt.Errorf("invalid length: %v != %v", length, len(s))
	}
	return s, nil
}

// ByteSlice is used to hex encode addresses in JSON structs.
type ByteSlice []byte

// String returns the bytes as a hexadecimal string.
func (bs ByteSlice) String() string {
	return hex.EncodeToString(bs)
}

func (bs ByteSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(bs.String())
}

func (bs *ByteSlice) UnmarshalJSON(data []byte) error {
	if string(data) == "null" || string(data) == `""` {
		return nil
	}
	s, err := hexDecode(data, -1)
	if err != nil {
		return err
	}
	*bs = s
	return nil
}
