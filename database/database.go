// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package database

import (
	"context"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

type Database interface {
	Close() error // Close database

	// SQL
	RegisterNotification(context.Context, NotificationName, NotificationCallback, any) error
	UnregisterNotification(NotificationName) error
}

type NotFoundError string

func (nfe NotFoundError) Error() string {
	return string(nfe)
}

func (nfe NotFoundError) Is(target error) bool {
	_, ok := target.(NotFoundError)
	return ok
}

type DuplicateError string

func (de DuplicateError) Error() string {
	return string(de)
}

func (de DuplicateError) Is(target error) bool {
	_, ok := target.(DuplicateError)
	return ok
}

type ValidationError string

func (ve ValidationError) Error() string {
	return string(ve)
}

func (ve ValidationError) Is(target error) bool {
	_, ok := target.(ValidationError)
	return ok
}

type ZeroRowsError string

func (ze ZeroRowsError) Error() string {
	return string(ze)
}

func (ze ZeroRowsError) Is(target error) bool {
	_, ok := target.(ZeroRowsError)
	return ok
}

var (
	ErrDuplicate  = DuplicateError("duplicate")
	ErrNotFound   = NotFoundError("not found")
	ErrValidation = ValidationError("validation")
)

// ByteArray is a type that corresponds to BYTEA in a database. It supports
// marshalling and unmarshalling from JSON, as well as implementing the
// sql.Scanner interface with NULL handling.
type ByteArray []byte

func (ba ByteArray) String() string {
	return hex.EncodeToString([]byte(ba))
}

func (ba ByteArray) MarshalJSON() ([]byte, error) {
	if ba == nil {
		return []byte("null"), nil
	}
	return []byte(fmt.Sprintf("\"\\\\x%s\"", hex.EncodeToString([]byte(ba)))), nil
}

func (ba *ByteArray) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*ba = nil
		return nil
	}
	// We expect a quoted escape prefixed (\\x) hexadecimal string.
	s := string(data)
	if !strings.HasPrefix(s, `"\\x`) || !strings.HasSuffix(s, `"`) {
		return errors.New("byte array does not have escape prefix")
	}
	b, err := hex.DecodeString(s[4 : len(s)-1])
	if err != nil {
		return err
	}
	*ba = b
	return nil
}

func (ba *ByteArray) Scan(value interface{}) error {
	if value == nil {
		*ba = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("not a byte array (%T)", value)
	}
	nba := make([]byte, len(b))
	copy(nba, b)
	*ba = nba
	return nil
}

func (ba ByteArray) Value() (driver.Value, error) {
	if ba == nil {
		return nil, nil
	}
	return []byte(ba), nil
}

// // XXX figure out why this doens't work
// func (ba *ByteArray) Value() (driver.Value, error) {
//	return *ba, nil
// }

var _ driver.Valuer = (*ByteArray)(nil)

// BigInt is a large integer data type that corresponds to a NUMERIC in
// a database.
type BigInt struct {
	*big.Int
}

func NewBigInt(bi *big.Int) *BigInt {
	return &BigInt{Int: bi}
}

func NewBigIntZero() *BigInt {
	return &BigInt{Int: new(big.Int)}
}

func (bi *BigInt) Cmp(a *BigInt) int {
	return bi.Int.Cmp(a.Int)
}

func (bi *BigInt) IsZero() bool {
	return bi.IsInt64() && bi.Int64() == 0
}

func (bi *BigInt) SetUint64(val uint64) *BigInt {
	if bi.Int == nil {
		bi.Int = new(big.Int)
	}
	bi.Int.SetUint64(val)
	return bi
}

func (bi BigInt) MarshalJSON() ([]byte, error) {
	if bi.Int == nil {
		return []byte("null"), nil
	}
	return bi.Int.MarshalJSON()
}

func (bi *BigInt) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		bi.Int = nil
		return nil
	}
	nbi := new(big.Int)
	if err := nbi.UnmarshalJSON(data); err != nil {
		return err
	}
	bi.Int = nbi
	return nil
}

func (bi *BigInt) Scan(value interface{}) error {
	if value == nil {
		bi.Int = nil
		return nil
	}

	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("not a byte array (%T)", value)
	}
	nbi := new(big.Int)
	if _, ok := nbi.SetString(string(b), 10); !ok {
		return fmt.Errorf("convert %q to BigInt", string(b))
	}
	bi.Int = nbi
	return nil
}

// bi should not be a pointer but it seems like we are pleasing the Valuer
// interface. This needs some additional testing.
func (bi *BigInt) Value() (driver.Value, error) {
	if bi == nil || bi.Int == nil {
		return nil, nil
	}
	return bi.Text(10), nil
}

var _ driver.Valuer = (*BigInt)(nil)

// Timestamp is a type that corresponds to a TIMESTAMP in a database. It
// supports marshalling and unmarshalling from JSON, as well as implementing
// the sql.Scanner interface with NULL handling.
type Timestamp struct {
	time.Time
}

const timestampFormat = `2006-01-02T15:04:05.999999999`

func NewTimestamp(time time.Time) Timestamp {
	return Timestamp{Time: time.Round(0).UTC()}
}

func (ts Timestamp) MarshalJSON() ([]byte, error) {
	if ts.IsZero() {
		return []byte("null"), nil
	}
	return []byte(ts.Format(`"` + timestampFormat + `"`)), nil
}

func (ts *Timestamp) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		ts.Time = time.Time{}
		return nil
	}
	var err error
	ts.Time, err = time.Parse(`"`+timestampFormat+`"`, string(data))
	if err != nil {
		return err
	}
	return nil
}

func (ts *Timestamp) Scan(value interface{}) error {
	if value == nil {
		ts.Time = time.Time{}
		return nil
	}
	var ok bool
	ts.Time, ok = value.(time.Time)
	if !ok {
		return fmt.Errorf("not a time (%T)", value)
	}
	return nil
}

func (ts Timestamp) Value() (driver.Value, error) {
	if ts.IsZero() {
		return nil, nil
	}
	return ts.Time.Format(time.RFC3339Nano), nil
}

var _ driver.Valuer = (*Timestamp)(nil)

// TimeZone is a type that encodes to and decodes from a +/-hh:mm string.
type TimeZone struct {
	hour   int
	minute int
	valid  bool
}

func (tz TimeZone) Equal(tzb TimeZone) bool {
	return tz.hour == tzb.hour && tz.minute == tzb.minute
}

func (tz *TimeZone) Parse(s string) error {
	if s == "" {
		tz.hour, tz.minute, tz.valid = 0, 0, false
	}
	if len(s) != len("+10:00") {
		return fmt.Errorf("%q has invalid length", s)
	}
	if s[0] != '-' && s[0] != '+' {
		return fmt.Errorf("invalid prefix %q (not +/-)", s[0])
	}
	if s[3] != ':' {
		return fmt.Errorf("invalid separator %q (not :)", s[3])
	}

	hour, err := strconv.Atoi(s[0:3])
	if err != nil || hour < -12 || hour > 14 {
		return fmt.Errorf("invalid hour %q", s[0:3])
	}
	minute, err := strconv.Atoi(s[4:6])
	if err != nil || minute < 0 || minute > 59 {
		return fmt.Errorf("invalid minute %q", s[4:6])
	}
	tz.hour, tz.minute, tz.valid = hour, minute, true

	return nil
}

func (tz TimeZone) String() string {
	return fmt.Sprintf("%+0.2d:%0.2d", tz.hour, tz.minute)
}

func (tz TimeZone) MarshalJSON() ([]byte, error) {
	if !tz.valid {
		return []byte("null"), nil
	}
	return []byte(`"` + tz.String() + `"`), nil
}

func (tz *TimeZone) UnmarshalJSON(data []byte) error {
	s := string(data)
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		s = s[1 : len(s)-1]
	}
	if s == "null" {
		tz.hour, tz.minute, tz.valid = 0, 0, false
		return nil
	}
	if err := tz.Parse(s); err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}
	return nil
}

func (tz *TimeZone) Scan(value interface{}) error {
	if value == nil {
		tz.hour, tz.minute, tz.valid = 0, 0, false
		return nil
	}
	s, ok := value.(string)
	if !ok {
		return fmt.Errorf("not a string (%T)", value)
	}
	if err := tz.Parse(s); err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}
	return nil
}

func (tz TimeZone) Value() (driver.Value, error) {
	if !tz.valid {
		return nil, nil
	}
	return tz.String(), nil
}

var _ driver.Valuer = (*TimeZone)(nil)

// NotificationCallback is a callback function for a database notification.
type NotificationCallback func(string, string, interface{}, interface{})

// NotificationName identifies a database notification type.
type NotificationName string
