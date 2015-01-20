package main

import (
	"encoding/binary"
	"flag"
	"io"
	"reflect"
	"strconv"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

const debug = true

type Nonce abstract.Secret

var aSecret abstract.Secret
var tSecret = reflect.TypeOf(&aSecret).Elem()

var aPoint abstract.Point
var tPoint = reflect.TypeOf(&aPoint).Elem()

var aNonce Nonce
var tNonce = reflect.TypeOf(&aNonce).Elem()


func WritePrefix(w io.Writer, p []byte) (n int, err error) {
	length := len(p)
	buf := make([]byte, 2)
	buf = append(buf, p...)
	binary.LittleEndian.PutUint16(buf[:2], uint16(length))
	return w.Write(buf)
}

func ReadPrefix(r io.Reader) ([]byte, error) {
	lenbuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenbuf); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint16(lenbuf)
	buf := make([]byte, length)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func main() {
	n := flag.Int("n", 3, "number of servers")
	k := flag.Int("k", 3, "share threshold")
	flag.Parse()
	if flag.NArg() < 1 {
		panic("must specify server index")
	}
	id, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		panic("server index must be an integer")
	}

	// Swappable crypto modules.
	suite := nist.NewAES128SHA256P256()
	random := random.Stream

	// Use a local setup for now.
	contextRandom := abstract.HashStream(suite, []byte("test"), nil)
	config := NewLocalPeerConfig(suite, contextRandom, id, *n, *k)

	context := NewContext(suite, random, config)
	NewServer(context).Start()
}
