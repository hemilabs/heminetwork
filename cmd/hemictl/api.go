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
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
)

var (
	reSkip         = regexp.MustCompile(`(?i)(Response|Notification)$`)
	allCommands    = make(map[string]reflect.Type)
	sortedCommands []string
)

func init() {
	for k, v := range tbcapi.APICommands() {
		allCommands[string(k)] = v
	}
	sortedCommands = make([]string, 0, len(allCommands))
	for k := range allCommands {
		sortedCommands = append(sortedCommands, k)
	}
	sort.Strings(sortedCommands)

	registerCommand("api", "generic RPC API commands", apiHandler)
}

func printJSON(where io.Writer, indent string, payload any) error {
	w := &bytes.Buffer{}
	fmt.Fprint(where, indent)
	e := json.NewEncoder(w)
	e.SetIndent(indent, "    ")
	if err := e.Encode(payload); err != nil {
		return fmt.Errorf("can't encode payload %T: %w", payload, err)
	}
	fmt.Fprint(where, w.String())
	return nil
}

// Jsonify converts key=value pairs to a JSON object string.
func Jsonify(args []string) (string, error) {
	formatted := "{"
	for i, c := range args {
		if i != 0 {
			formatted += ","
		}
		kv := strings.SplitN(c, "=", 2)
		if len(kv) != 2 {
			return formatted, fmt.Errorf("invalid argument format: %v", c)
		}
		formatted = fmt.Sprintf("%s\"%s\": %v", formatted, kv[0], kv[1])
	}
	formatted += "}"

	return formatted, nil
}

// argsFromType derives an argument map from a struct type's JSON field tags.
// Each exported field with a json tag becomes an optional argument.
func argsFromType(t reflect.Type) map[string]argument {
	args := make(map[string]argument)
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		args[name] = argument{help: f.Type.String()}
	}
	return args
}

// payloadFromMap builds a typed request payload from a string map.
// Values are Jsonified unquoted so that numeric strings become JSON numbers,
// preserving correct unmarshaling into uint/int/float fields.
func payloadFromMap(cmdType reflect.Type, args map[string]string) (any, error) {
	clone := reflect.New(cmdType).Interface()
	if len(args) == 0 {
		return clone, nil
	}
	kvs := make([]string, 0, len(args))
	for k, v := range args {
		kvs = append(kvs, k+"="+v)
	}
	b, err := Jsonify(kvs)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(b), clone); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	return clone, nil
}

// hemictlAPI satisfies the protocol.API interface.
type hemictlAPI struct {
	api string
}

// Commands satisfies the protocol.API interface.
func (f *hemictlAPI) Commands() map[protocol.Command]reflect.Type {
	switch f.api {
	case "tbcapi":
		return tbcapi.APICommands()
	}
	return nil
}

func apiCall(ctx context.Context, api string, URL string, cmd any) (any, error) {
	conn, err := protocol.NewConn(URL, &protocol.ConnOptions{
		ReadLimit: tbcReadLimit,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tctx, tcancel := context.WithTimeout(ctx, callTimeout)
	defer tcancel()
	go func() {
		for {
			if _, _, _, err := conn.Read(tctx, &hemictlAPI{api: api}); err != nil {
				return
			}
		}
	}()

	_, _, payload, err := conn.Call(tctx, &hemictlAPI{api: api}, cmd)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return payload, nil
}

// buildApiGroup dynamically constructs a commandGroup from the registered API
// commands. Each request type (non-Response, non-Notification) becomes one
// command whose args are derived from the struct's JSON field tags.
func buildApiGroup() commandGroup {
	cmds := make(map[string]command, len(allCommands))
	for rawName, cmdType := range allCommands {
		if reSkip.MatchString(rawName) {
			continue
		}
		name, ct := rawName, cmdType

		var (
			apiName string
			url     string
		)
		switch {
		case strings.HasPrefix(name, "tbcapi"):
			apiName = "tbcapi"
			url = tbcapi.DefaultURL
		default:
			continue // no known endpoint; skip
		}

		cmds[name] = command{
			help: "Send " + name + " RPC request.",
			args: argsFromType(ct),
			run: func(ctx context.Context, args map[string]string) error {
				payload, err := payloadFromMap(ct, args)
				if err != nil {
					return err
				}
				response, err := apiCall(ctx, apiName, url, payload)
				if err != nil {
					return err
				}
				log.Debugf("%v", spew.Sdump(response))
				return printJSON(os.Stdout, "", response)
			},
		}
	}
	return commandGroup{
		help:     "Generic RPC API commands.",
		commands: cmds,
	}
}

func apiHandler(pctx context.Context, flags []string) error {
	grp := buildApiGroup()

	fs := flag.NewFlagSet("api", flag.ExitOnError)
	helpShort := fs.Bool("h", false, "display help")
	helpLong := fs.Bool("help", false, "display help")
	helpVerbose := fs.Bool("help-verbose", false, "display verbose help with JSON request/response examples")
	fs.Usage = func() { printGroupHelp("api", grp) }
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(flags) == 0 || *helpShort || *helpLong {
		fs.Usage()
		return nil
	}
	if *helpVerbose {
		fmt.Fprintf(os.Stderr, "%v\n\n", welcome)
		for _, name := range sortedCommands {
			cmdType := allCommands[name]
			clone := reflect.New(cmdType).Interface()
			fmt.Fprintf(os.Stderr, "%v:\n", name)
			_ = printJSON(os.Stderr, "  ", clone)
			fmt.Fprintf(os.Stderr, "\n")
		}
		return nil
	}

	return dispatchGroup(pctx, grp, "api", fs.Args())
}
