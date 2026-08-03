// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hemilabs/heminetwork/v2/service/hproxy"
)

func httpCall(ctx context.Context, method, url string, requestBody io.Reader) (io.ReadCloser, error) {
	c := http.DefaultClient
	req, err := http.NewRequestWithContext(ctx, method, url, requestBody)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	reply, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.do: %w", err)
	}
	switch reply.StatusCode {
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("status %v", reply.StatusCode)
	}
	return reply.Body, nil
}

func init() {
	registerCommand("hproxy", "hproxy controller", hproxyHandler)
}

func hproxyHandler(pctx context.Context, flags []string) error {
	grp := commandGroup{
		help: "Control a running hproxy instance.",
		commands: map[string]command{
			"add": {
				help: "Register one or more HVM nodes with hproxy.",
				args: map[string]argument{
					"hproxy": {defaultValue: hproxy.DefaultControlAddress, help: "hproxy control address"},
					"hvm":    {required: true, help: "comma-separated list of HVM node URLs to add"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					hvms := strings.Split(args["hvm"], ",")
					r := make([]map[string]any, len(hvms))
					for k := range hvms {
						r[k] = map[string]any{"node_url": hvms[k]}
					}
					req, err := json.Marshal(r)
					if err != nil {
						return fmt.Errorf("request: %w", err)
					}
					body, err := httpCall(ctx, http.MethodGet,
						"http://"+args["hproxy"]+hproxy.RouteControlAdd,
						bytes.NewReader(req))
					if err != nil {
						return err
					}
					defer body.Close()
					var jr []map[string]any
					if err := json.NewDecoder(body).Decode(&jr); err != nil {
						return fmt.Errorf("decode: %w", err)
					}
					for _, v := range jr {
						fmt.Printf("node: %v error: %v\n", v["node_url"], v["error"])
					}
					return nil
				},
			},
			"list": {
				help: "List all HVM nodes registered with hproxy.",
				args: map[string]argument{
					"hproxy": {defaultValue: hproxy.DefaultControlAddress, help: "hproxy control address"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					body, err := httpCall(ctx, http.MethodGet,
						"http://"+args["hproxy"]+hproxy.RouteControlList, nil)
					if err != nil {
						return err
					}
					defer body.Close()
					var jr []map[string]any
					if err := json.NewDecoder(body).Decode(&jr); err != nil {
						return fmt.Errorf("decode: %w", err)
					}
					for _, v := range jr {
						fmt.Printf("node: %v status: %v connections: %v\n",
							v["node_url"], v["status"], v["connections"])
					}
					return nil
				},
			},
			"remove": {
				help: "Deregister one or more HVM nodes from hproxy.",
				args: map[string]argument{
					"hproxy": {defaultValue: hproxy.DefaultControlAddress, help: "hproxy control address"},
					"hvm":    {required: true, help: "comma-separated list of HVM node URLs to remove"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					hvms := strings.Split(args["hvm"], ",")
					r := make([]map[string]any, len(hvms))
					for k := range hvms {
						r[k] = map[string]any{"node_url": hvms[k]}
					}
					req, err := json.Marshal(r)
					if err != nil {
						return fmt.Errorf("request: %w", err)
					}
					body, err := httpCall(ctx, http.MethodGet,
						"http://"+args["hproxy"]+hproxy.RouteControlRemove,
						bytes.NewReader(req))
					if err != nil {
						return err
					}
					defer body.Close()
					var jr []map[string]any
					if err := json.NewDecoder(body).Decode(&jr); err != nil {
						return fmt.Errorf("decode: %w", err)
					}
					for _, v := range jr {
						fmt.Printf("node: %v error: %v\n", v["node_url"], v["error"])
					}
					return nil
				},
			},
		},
	}

	fs := flag.NewFlagSet("hproxy", flag.ExitOnError)
	helpShort := fs.Bool("h", false, "display help")
	helpLong := fs.Bool("help", false, "display help")
	fs.Usage = func() { printGroupHelp("hproxy", grp) }
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(flags) == 0 || *helpShort || *helpLong {
		fs.Usage()
		return nil
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	return dispatchGroup(ctx, grp, "hproxy", fs.Args())
}
