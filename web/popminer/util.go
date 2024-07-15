// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
	"strings"
	"syscall/js"
	"time"
	"unsafe"

	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/service/popm"
)

var (
	promiseConstructor = js.Global().Get("Promise")
	objectConstructor  = js.Global().Get("Object")
	arrayConstructor   = js.Global().Get("Array")
)

// JSMarshaler is the interface implemented by types that can marshal
// themselves into a valid JavaScript value.
type JSMarshaler interface {
	MarshalJS() (js.Value, error)
}

// jsValueOf returns x as a JavaScript value.
// If the x cannot be converted to a JavaScript value, js.Undefined() will be
// returned and an error will be logged.
//
//	| Go                     | JavaScript             |
//	| ---------------------- | ---------------------- |
//	| nil                    | null                   |
//	| js.Value               | [value]                |
//	| js.Func                | function               |
//	| JSMarshaler            | output of MarshalJS()  |
//	| bool                   | boolean                |
//	| integers and floats    | number                 |
//	| string                 | string                 |
//	| []any and [x]any       | Array                  |
//	| map[string]any         | Object                 |
//	| struct                 | Object                 |
//	| all others             | undefined              |
func jsValueOf(x any) js.Value {
	v, err := jsValueSafe(x)
	if err != nil {
		return jsReflectValueOf(reflect.ValueOf(x))
	}
	return v
}

func jsReflectValueOf(rv reflect.Value) js.Value {
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return js.Null()
		}
		return jsReflectValueOf(rv.Elem())
	case reflect.Slice, reflect.Array:
		if rv.IsNil() {
			return js.Null()
		}
		a := arrayConstructor.New(rv.Len())
		for i := range rv.Len() {
			a.SetIndex(i, jsReflectValueOf(rv.Index(i)))
		}
		return a
	case reflect.Map:
		if rv.IsNil() {
			return js.Null()
		}
		o := objectConstructor.New()
		i := rv.MapRange()
		for i.Next() {
			k, ok := i.Key().Interface().(string)
			if !ok {
				// Non-string keys are unsupported.
				log.Errorf("cannot encode map with non-string key %v",
					i.Key().Type())
				return js.Undefined()
			}
			o.Set(k, jsReflectValueOf(i.Value()))
		}
		return o
	case reflect.Struct:
		return jsReflectStruct(rv)
	default:
		if !rv.CanInterface() {
			log.Errorf("cannot encode reflect value of type %v", rv.Type())
			return js.Undefined()
		}
		v, err := jsValueSafe(rv.Interface())
		if err != nil {
			log.Errorf("cannot encode %v: %v", rv.Type(), err)
		}
		return v
	}
}

// jsReflectStruct converts a Go struct to a JavaScript Object, using the 'json'
// struct field tags similar to the encoding/json package.
//
// Note: This may not handle anonymous or embedded structs and other uncommon
// types inside structs, additionally the 'string' json tag option is not
// supported.
func jsReflectStruct(rv reflect.Value) js.Value {
	o := objectConstructor.New()
	t := rv.Type()
	for i := range t.NumField() {
		f := rv.Field(i)
		if !f.CanInterface() {
			continue
		}
		sf := t.Field(i)

		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts := parseJSONTag(tag)
		if name == "" {
			name = sf.Name
		}

		if opts.Contains("omitempty") && isEmptyValue(f) {
			continue
		}
		o.Set(name, jsReflectValueOf(f))
	}
	return o
}

type jsonOptions []string

func (o jsonOptions) Contains(optionName string) bool {
	for _, option := range o {
		if option == optionName {
			return true
		}
	}
	return false
}

func parseJSONTag(tag string) (string, jsonOptions) {
	tag, opt, _ := strings.Cut(tag, ",")
	return tag, strings.Split(opt, ",")
}

func isEmptyValue(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return rv.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return rv.IsZero()
	default:
		return false
	}
}

// jsValueSafe returns a JavaScript value representing x.
// It handles all types handled by js.ValueOf, and includes some special
// handling for JSMarshaler. If a type cannot be converted to a js.Value,
// js.Undefined() and an error will be returned.
//
// This function will not attempt reflection, use jsValueOf for
// reflection-based handling for structs.
//
//	| Go                     | JavaScript             |
//	| ---------------------- | ---------------------- |
//	| nil                    | null                   |
//	| js.Value               | [value]                |
//	| js.Func                | function               |
//	| JSMarshaler            | output of MarshalJS()  |
//	| bool                   | boolean                |
//	| integers and floats    | number                 |
//	| string                 | string                 |
//	| []any and [x]any       | Array                  |
//	| map[string]any         | Object                 |
//	| all others             | undefined (err != nil) |
func jsValueSafe(x any) (js.Value, error) {
	switch t := x.(type) {
	case nil:
		return js.Null(), nil
	case js.Value:
		return t, nil
	case js.Func:
		return t.Value, nil
	case JSMarshaler:
		jsv, err := t.MarshalJS()
		if err != nil {
			return js.Undefined(), err
		}
		return jsv, nil
	case bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		uintptr, unsafe.Pointer,
		float32, float64, string:
		return js.ValueOf(t), nil
	case []any:
		a := arrayConstructor.New(len(t))
		for i, s := range t {
			a.SetIndex(i, s)
		}
		return a, nil
	case map[string]any:
		o := objectConstructor.New()
		for k, v := range t {
			o.Set(k, v)
		}
		return o, nil
	default:
		err := fmt.Errorf("cannot create js.Value for %T: unsupported", x)
		return js.Undefined(), err
	}
}

// codedError represents an error that has a related [ErrorCode].
type codedError struct {
	code ErrorCode
	err  error
}

// errorWithCode returns an error containing the given error code.
func errorWithCode(code ErrorCode, err error) error {
	return codedError{
		code: code,
		err:  err,
	}
}

// codeFromError returns the error code from the error, if possible, otherwise
// ErrorCodeInternal will be returned.
func codeFromError(err error) ErrorCode {
	var ce codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return ErrorCodeInternal
}

// Error returns the error string.
func (c codedError) Error() string {
	return c.err.Error()
}

// Unwrap returns the wrapped error.
func (c codedError) Unwrap() error {
	return c.err
}

// jsError returns a [js.Value] representing the given error. The error code
// will be extracted from the given error using codeFromError, if available,
// otherwise the error code will be ErrorCodeInternal.
func jsError(err error) js.Value {
	return newJSError(codeFromError(err), err.Error())
}

// jsErrorWithCode returns a [js.Value] representing the given error with
// an error code.
func jsErrorWithCode(code ErrorCode, err error) js.Value {
	return newJSError(code, err.Error())
}

// newJSError returns a new [js.Value] for an [Error] with the given code and
// message. The stack will be generated, skipping stackSkip callers. The
// timestamp will be set to time.Now() in Unix seconds.
func newJSError(code ErrorCode, message string) js.Value {
	return jsValueOf(Error{
		Code:      code,
		Message:   message,
		Stack:     string(debug.Stack()),
		Timestamp: time.Now().Unix(),
	})
}

// convertL2Keystone converts a [hemi.L2Keystone] to an L2Keystone.
func convertL2Keystone(ks *hemi.L2Keystone) L2Keystone {
	if ks == nil {
		panic("convertL2Keystone: cannot handle nil *hemi.L2Keystone")
	}

	return L2Keystone{
		Version:            ks.Version,
		L1BlockNumber:      ks.L1BlockNumber,
		L2BlockNumber:      ks.L2BlockNumber,
		ParentEPHash:       ks.ParentEPHash.String(),
		PrevKeystoneEPHash: ks.PrevKeystoneEPHash.String(),
		StateRoot:          ks.StateRoot.String(),
		EPHash:             ks.EPHash.String(),
	}
}

// convertEvent converts a popm event struct to a WASM popm event struct.
func convertEvent(data any) any {
	switch d := data.(type) {
	case popm.EventMineKeystone:
		return EventMineKeystone{
			Keystone: convertL2Keystone(d.Keystone),
		}
	case popm.EventTransactionBroadcast:
		return EventTransactionBroadcast{
			Keystone: convertL2Keystone(d.Keystone),
			TxHash:   d.TxHash,
		}
	default:
		log.Errorf("unknown popm event: %T", data)
		return nil
	}
}
