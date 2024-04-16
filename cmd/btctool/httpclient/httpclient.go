// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func Request(ctx context.Context, method, url string, body any) ([]byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		r = bytes.NewReader(b)
	}
	c := &http.Client{}
	for retry := 1; ; retry++ {
		req, err := http.NewRequestWithContext(ctx, method, url, r)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request: %w", err)
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusTooManyRequests:
			time.Sleep(time.Duration(retry) * time.Second)
			continue
		default:
			return nil, fmt.Errorf("%v %v %v %v", method, url,
				resp.StatusCode, http.StatusText(resp.StatusCode))
		}

		return io.ReadAll(resp.Body)
	}
}
