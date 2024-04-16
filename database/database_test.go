// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
)

func TestStructByteArrayJSON(t *testing.T) {
	type X struct {
		Y           BigInt
		Ts          Timestamp
		MyByteArray ByteArray
	}

	y := NewBigIntZero().SetUint64(15)
	x := X{
		Y:           *y,
		Ts:          NewTimestamp(time.Now()),
		MyByteArray: []byte{0x01, 0x02},
	}
	jx, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	var xx X
	err = json.Unmarshal(jx, &xx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(x, xx) {
		t.Fatalf("not equal %v%v", spew.Sdump(x), spew.Sdump(xx))
	}
}

func TestByteArrayJSON(t *testing.T) {
	tests := []struct {
		data    []byte
		want    []byte
		wantErr bool
	}{
		{
			data: []byte(`"\\x1234"`),
			want: []byte{0x12, 0x34},
		},
		{
			data: []byte(`"\\x0102030405060708090a0b0c0d0e0f01"`),
			want: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01,
			},
		},
		{
			data: []byte("null"),
			want: nil,
		},
		{
			data:    []byte(`\\x1234`),
			wantErr: true,
		},
		{
			data:    []byte(`"1234"`),
			wantErr: true,
		},
		{
			data:    []byte(`""`),
			wantErr: true,
		},
		{
			data:    []byte(`"\x1"`),
			wantErr: true,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("bytearray-%d", i), func(t *testing.T) {
			var ba ByteArray
			switch err := ba.UnmarshalJSON(test.data); {
			case err != nil && !test.wantErr:
				t.Errorf("UnmarshalJSON failed: %v", err)
			case err == nil && test.wantErr:
				t.Error("UnmarshalJSON succeeded, want error")
			case err == nil && !test.wantErr:
				if !bytes.Equal([]byte(ba), test.want) {
					t.Errorf("UnmarshalJSON = %v, want %v", ba, test.want)
				}
			}

			if test.wantErr {
				return
			}

			b, err := ba.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON failed: %v", err)
			}
			if !bytes.Equal(b, test.data) {
				t.Errorf("MarshalJSON = %v, want %v", b, test.data)
			}
		})
	}
}

func TestByteArrayScan(t *testing.T) {
	tests := []struct {
		src  interface{}
		want ByteArray
	}{
		{
			src:  nil,
			want: ByteArray(nil),
		},
		{
			src:  []byte{},
			want: ByteArray{},
		},
		{
			src:  []byte{0x12, 0x34},
			want: ByteArray{0x12, 0x34},
		},
	}
	for _, test := range tests {
		var ba ByteArray
		if err := ba.Scan(test.src); err != nil {
			t.Fatalf("Failed to scan: %v", err)
		}
		if !bytes.Equal(ba, test.want) {
			t.Errorf("Got %v, want %v", ba, test.want)
		}
	}
}

func TestByteArrayScanReuse(t *testing.T) {
	b := []byte{0x12, 0x34}
	want := make([]byte, len(b))
	copy(want, b)

	var ba ByteArray
	if err := ba.Scan(b); err != nil {
		t.Fatalf("Failed to scan: %v", err)
	}
	b[0], b[1] = 0xff, 0xff
	if !bytes.Equal(ba, want) {
		t.Errorf("Got %v, want %v", ba, want)
	}
}

func TestTimestampJSON(t *testing.T) {
	tests := []struct {
		data    []byte
		want    Timestamp
		wantErr bool
	}{
		{
			data: []byte(`"2022-05-11T15:23:31.723583"`),
			want: Timestamp{Time: time.Date(2022, 5, 11, 15, 23, 31, 723583000, time.UTC)},
		},
		{
			data: []byte("null"),
			want: Timestamp{},
		},
		{
			data:    []byte(`""`),
			wantErr: true,
		},
		{
			data:    []byte(`"2022-05-11"`),
			wantErr: true,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("timestamp-%d", i), func(t *testing.T) {
			var ts Timestamp
			err := ts.UnmarshalJSON(test.data)
			switch {
			case err != nil && !test.wantErr:
				t.Errorf("UnmarshalJSON failed: %v", err)
			case err == nil && test.wantErr:
				t.Error("UnmarshalJSON succeeded, want error")
			case err == nil && !test.wantErr:
				if !ts.Equal(test.want.Time) {
					t.Errorf("UnmarshalJSON = %v, want %v", ts, test.want)
				}
			}

			if test.wantErr {
				return
			}

			b, err := ts.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON failed: %v", err)
			}
			if !bytes.Equal(b, test.data) {
				t.Errorf("MarshalJSON = %v, want %v", b, test.data)
			}
		})
	}
}

func TestTimestampScan(t *testing.T) {
	tests := []struct {
		src  interface{}
		want Timestamp
	}{
		{
			src:  nil,
			want: Timestamp{},
		},
		{
			src:  time.Date(2022, 5, 11, 15, 23, 31, 723583000, time.UTC),
			want: Timestamp{Time: time.Date(2022, 5, 11, 15, 23, 31, 723583000, time.UTC)},
		},
	}
	for _, test := range tests {
		var ts Timestamp
		if err := ts.Scan(test.src); err != nil {
			t.Fatalf("Failed to scan: %v", err)
		}
		if !ts.Equal(test.want.Time) {
			t.Errorf("Got %v, want %v", ts, test.want)
		}
	}
}

func TestTimeZoneJSON(t *testing.T) {
	tests := []struct {
		data    []byte
		want    TimeZone
		wantErr bool
	}{
		{
			data: []byte(`"-09:30"`),
			want: TimeZone{hour: -9, minute: 30},
		},
		{
			data: []byte(`"+10:00"`),
			want: TimeZone{hour: 10, minute: 0},
		},
		{
			data: []byte("null"),
			want: TimeZone{},
		},
		{
			data:    []byte(`""`),
			wantErr: true,
		},
		{
			data:    []byte(`"10:00"`),
			wantErr: true,
		},
		{
			data:    []byte(`"+9:00"`),
			wantErr: true,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("timestamp-%d", i), func(t *testing.T) {
			var tz TimeZone
			switch err := tz.UnmarshalJSON(test.data); {
			case err == nil && test.wantErr:
				t.Error("UnmarshalJSON succeeded, want error")
			case err != nil && !test.wantErr:
				t.Errorf("UnmarshalJSON failed: %v", err)
			case err == nil && !test.wantErr:
				if !tz.Equal(test.want) {
					t.Errorf("UnmarshalJSON = %v, want %v", tz, test.want)
				}
			}

			if test.wantErr {
				return
			}

			b, err := tz.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON failed: %v", err)
			}
			if !bytes.Equal(b, test.data) {
				t.Errorf("MarshalJSON = %v, want %v", b, test.data)
			}
		})
	}
}

func TestTimeZoneScan(t *testing.T) {
	tests := []struct {
		src     interface{}
		want    TimeZone
		wantErr bool
	}{
		{
			src:  nil,
			want: TimeZone{},
		},
		{
			src:  "-09:30",
			want: TimeZone{hour: -9, minute: 30},
		},
		{
			src:  "+10:00",
			want: TimeZone{hour: 10, minute: 0},
		},
		{
			src:     "10:00",
			wantErr: true,
		},
	}
	for _, test := range tests {
		var tz TimeZone
		switch err := tz.Scan(test.src); {
		case err == nil && test.wantErr:
			t.Errorf("Got nil error for %q, want error", test.src)
		case err != nil && !test.wantErr:
			t.Errorf("Failed to scan %q: %v", test.src, err)
		case err == nil && !test.wantErr:
			if !tz.Equal(test.want) {
				t.Errorf("Got %v, want %v", tz, test.want)
			}
		}
	}
}
