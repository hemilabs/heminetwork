// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"reflect"
	"runtime/debug"
	"strings"
	"syscall/js"
	"time"
)

var (
	promiseConstructor = js.Global().Get("Promise")
	objectConstructor  = js.Global().Get("Object")
	arrayConstructor   = js.Global().Get("Array")
)

// jsValueOf returns x as a JavaScript value.
//
//	| Go                     | JavaScript             |
//	| ---------------------- | ---------------------- |
//	| nil                    | null                   |
//	| js.Value               | [value]                |
//	| js.Func                | function               |
//	| bool                   | boolean                |
//	| integers and floats    | number                 |
//	| string                 | string                 |
//	| []any and [x]any       | Array                  |
//	| map[string]any         | Object                 |
//	| struct                 | Object                 |
//	| all others             | undefined              |
func jsValueOf(x any) js.Value {
	switch t := x.(type) {
	case nil:
		return js.Null()
	case js.Value:
		return t
	case js.Func:
		return t.Value
	case bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, uintptr,
		float32, float64, string:
		return js.ValueOf(t)
	case []any:
		a := arrayConstructor.New(len(t))
		for i, s := range t {
			a.SetIndex(i, s)
		}
		return a
	case map[string]any:
		o := objectConstructor.New()
		for k, v := range t {
			o.Set(k, v)
		}
		return o
	default:
		// Attempt reflection, will fall back to using jsValueSafe.
		return jsReflectValueOf(reflect.ValueOf(x))
	}
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
				log.Warningf("cannot encode map with non-string key %v",
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
			log.Warningf("cannot encode reflect value of type %v", rv.Type())
			return js.Undefined()
		}
		return jsValueSafe(rv.Interface())
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
	return jsValueOf(Error{
		Message:   err.Error(),
		Stack:     stack,
		Timestamp: time.Now().Unix(),
	})
}
