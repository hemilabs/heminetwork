package continuum

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestEncryptDecrypt(t *testing.T) {
	server, err := NewTransport(CurveX25519, "")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTransport(CurveX25519, "")
	if err != nil {
		t.Fatal(err)
	}

	// Set keys to simulate incomming key exchange message
	server.them, err = server.curve.NewPublicKey(client.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	client.them, err = client.curve.NewPublicKey(server.us.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Perform actual key exchange
	err = server.kx()
	if err != nil {
		t.Fatal(err)
	}
	err = client.kx()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(server.encryptionKey[:], client.encryptionKey[:]) {
		t.Fatal("shared key not equal")
	}

	message := []byte("this is a super secret message y'all!")
	em, err := server.encrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	cleartext, err := client.decrypt(em[3:]) // clip size that is done by read normally
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, cleartext) {
		t.Fatal("message not equal")
	}
}

func TestNewCommand(t *testing.T) {
	helloChallenge := make([]byte, 32)
	helloRequest := &HelloRequest{
		Version:   TransportVersion,
		Options:   nil,
		Challenge: helloChallenge,
	}
	m := make(map[reflect.Type]PayloadType)
	m[reflect.TypeOf(helloRequest)] = PHelloRequest
	t.Logf("%v", m[reflect.TypeOf(helloRequest)])

	hash, payload, err := NewPayloadFromCommand(helloRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", spew.Sdump(hash))
	t.Logf("%v", spew.Sdump(payload))

	var x any
	x = helloRequest
	header := Header{
		PayloadType: m[reflect.TypeOf(x)],
		PayloadHash: *hash,
	}
	t.Logf("header: %v", spew.Sdump(header))
	jh, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", spew.Sdump(append(jh, payload...)))
}
