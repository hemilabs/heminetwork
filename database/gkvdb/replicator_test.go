package gkvdb

import (
	"bytes"
	"io"
	"reflect"
	"strconv"
	"testing"

	"github.com/kelindar/binary"
)

// XXX antonio, add gob test and run benchmarks so that we can decide between
// gob and kelindar.

func TestJournalEncoding(t *testing.T) {
	jop := &journalOp{
		Op:    opDel,
		Table: "table",
		Key:   []byte("key"),
		Value: []byte("value"),
	}
	e, err := binary.Marshal(jop)
	if err != nil {
		t.Fatal(err)
	}
	var d journalOp
	err = binary.Unmarshal(e, &d)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*jop, d) {
		t.Fatal("not equal")
	}
}

func TestJournalStream(t *testing.T) {
	maxItems := 199

	var b bytes.Buffer
	encoder := binary.NewEncoder(&b)
	for i := 0; i < maxItems; i++ {
		err := encoder.Encode(&journalOp{
			Op:    opDel,
			Table: "table",
			Key:   []byte("key" + strconv.Itoa(i)),
			Value: []byte("value" + strconv.Itoa(i)),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	d := binary.NewDecoder(&b)
	for i := 0; ; i++ {
		jop := journalOp{} // Yes, always allocate
		err := d.Decode(&jop)
		if err != nil {
			if err == io.EOF {
				if i != maxItems {
					t.Fatalf("i != maxItems, %v != %v", i, maxItems)
				}
				break
			}
			t.Fatal(err)
		}
		jopExected := journalOp{
			Op:    opDel,
			Table: "table",
			Key:   []byte("key" + strconv.Itoa(i)),
			Value: []byte("value" + strconv.Itoa(i)),
		}
		if !reflect.DeepEqual(jopExected, jop) {
			t.Fatal("not equal")
		}
	}
}
