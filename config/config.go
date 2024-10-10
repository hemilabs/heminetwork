// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type PrintMode int

const (
	PrintSecret PrintMode = iota
	PrintAll
	PrintNothing
)

var Align = 0 // Cleartext alignment, if not set it is autodetected

type Config struct {
	Value        any       // Value
	DefaultValue any       // Default value if Value is not set
	Help         string    // One line help
	Print        PrintMode // Print mode
	Required     bool      // If true, error out with error
	Parse        func(envValue string) (any, error)
}

type CfgMap map[string]Config

func Parse(c CfgMap) error {
	for k, v := range c {
		// Make sure v.Value is a pointer
		if reflect.TypeOf(v.Value).Kind() != reflect.Pointer {
			return errors.New("value must be a pointer")
		}
		// Make sure we are pointing to the same type
		if reflect.TypeOf(v.Value).Elem() != reflect.TypeOf(v.DefaultValue) {
			return fmt.Errorf("value not the same type as DefaultValue, "+
				"wanted %v got %v", reflect.TypeOf(v.Value).Elem(),
				reflect.TypeOf(v.DefaultValue))
		}

		envValue := os.Getenv(k)
		if envValue == "" {
			// Error out if this is not provided
			if v.Required {
				return fmt.Errorf("%v: must be set", k)
			}

			// Set v.Value to v.DefaultValue
			reflect.ValueOf(v.Value).Elem().Set(reflect.ValueOf(v.DefaultValue))
		} else {
			if v.Parse != nil {
				val, err := v.Parse(envValue)
				if err != nil {
					return fmt.Errorf("invalid value for %v: %v", k, err)
				}
				reflect.ValueOf(v.Value).Elem().Set(reflect.ValueOf(val))
				return nil
			}

			switch reflect.TypeOf(v.Value).Elem().Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16,
				reflect.Int32, reflect.Int64:

				evTyped, err := strconv.ParseInt(envValue, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid integer for %v: %v",
						k, err)
				}
				reflect.ValueOf(v.Value).Elem().SetInt(evTyped)

			case reflect.Uint, reflect.Uint8, reflect.Uint16,
				reflect.Uint32, reflect.Uint64:

				evTyped, err := strconv.ParseUint(envValue, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid unsigned for %v: %v",
						k, err)
				}
				reflect.ValueOf(v.Value).Elem().SetUint(evTyped)

			case reflect.String:
				reflect.ValueOf(v.Value).Elem().SetString(envValue)

			case reflect.Bool:
				val, err := strconv.ParseBool(envValue)
				if err != nil {
					return err
				}

				reflect.ValueOf(v.Value).Elem().SetBool(val)
			case reflect.Slice:
				value := reflect.ValueOf(v.Value).Elem()
				value.Set(reflect.AppendSlice(value, reflect.ValueOf(strings.Split(envValue, ","))))

			default:
				return fmt.Errorf("unsuported type for %v: %v",
					k, reflect.TypeOf(v.Value).Elem().Kind())
			}
		}
	}

	return nil
}

func PrintableConfig(c CfgMap) []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
		if Align < len(k) {
			Align = len(k)
		}
	}
	sort.Strings(keys)

	p := make([]string, 0, len(c))
	for k := range keys {
		key := keys[k]

		switch c[key].Print {
		case PrintAll:
			val := reflect.ValueOf(c[key].Value).Elem()
			p = append(p, fmt.Sprintf("%-*s: %v", Align, key, val))
		case PrintSecret:
			p = append(p, fmt.Sprintf("%-*s: %v", Align, key, "********"))
		}
	}
	return p
}

func Help(w io.Writer, c CfgMap) {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
		if Align < len(k) {
			Align = len(k)
		}
	}
	sort.Strings(keys)

	for k := range keys {
		key := keys[k]
		required := ""
		if c[key].Required {
			required = "(required) "
		}
		def := ""
		if c[key].DefaultValue != "" {
			def = fmt.Sprintf("(default: %v)", c[key].DefaultValue)
		}
		fmt.Fprintf(w, "\t%-*s: %v %v%v\n",
			Align, key, c[key].Help, required, def)
	}
}
