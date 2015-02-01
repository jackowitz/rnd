package main

import (
	"flag"
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

	// Determine the context and protocol at runtime.
	context := NewContext(suite, random, config)

	if id == 0 {
		NewLeaderSession().Start()
	} else {
		NewSession().Start()
	}
}
