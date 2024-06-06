// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"runtime/debug"
	"syscall/js"
	"time"

	"github.com/hemilabs/heminetwork/api"
)

var (
	promiseConstructor = js.Global().Get("Promise")
	objectConstructor  = js.Global().Get("Object")
	arrayConstructor   = js.Global().Get("Array")
)

// Object represents a JavaScript Object.
type Object map[string]any

// Value returns a [js.Value] containing a JavaScript Object for the object.
func (o Object) Value() js.Value {
	obj := objectConstructor.New()
	for k, v := range o {
		switch t := v.(type) {
		case Object:
			obj.Set(k, t.Value())
		case []Object:
			a := arrayConstructor.New(len(t))
			for i, so := range t {
				a.SetIndex(i, so.Value())
			}
			obj.Set(k, a)
		case api.ByteSlice:
			// Special handling for api.ByteSlice.
			// calls String() to return value as a hexadecimal encoded string
			obj.Set(k, t.String())
		default:
			obj.Set(k, jsValueSafe(v))
		}
	}
	return obj
}

// jsValueSafe wraps js.ValueOf and recovers when js.ValueOf panics due to it
// not being able to handle the type it is called with. js.Undefined() is
// returned when a panic occurs and an error is logged.
func jsValueSafe(v any) (jsv js.Value) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from js.ValueOf panic: %v: %T", r, v)
			jsv = js.Undefined()
		}
	}()
	return js.ValueOf(v)
}

// jsError returns a [js.Value] representing the given error.
func jsError(err error) js.Value {
	log.Tracef("jsError: %v", err)
	defer log.Tracef("jsError exit")

	stack := string(debug.Stack())
	return Object{
		"message":   err.Error(),
		"stack":     stack,
		"timestamp": time.Now().Unix(),
	}.Value()
}
