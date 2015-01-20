package main

import (
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
)

type Peer struct {
	Id int
	Addr string

	PrivKey abstract.Secret
	PubKey abstract.Point
}

type PeerConfig struct {
	Peers []Peer
	Mine, N, K int
}

func (p *PeerConfig) Self() *Peer {
	return &p.Peers[p.Mine]
}

func (p *PeerConfig) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	return encoder.Encode(p)
}

func (p *PeerConfig) FromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(file)
	return decoder.Decode(p)
}

// Generate a new configuration for running locally.
func NewLocalPeerConfig(suite abstract.Suite,
		random cipher.Stream, mine, n, k int) *PeerConfig {

	peers := make([]Peer, n)
	for i := range peers {
		addr := fmt.Sprintf("localhost:%d", 8080 + i)

		x := suite.Secret().Pick(random)
		X := suite.Point().Mul(nil, x)

		peers[i] = Peer{ i, addr, x, X }
	}
	return &PeerConfig{ peers, mine, n, k }
}

type Context struct {
	Suite abstract.Suite
	Random cipher.Stream

	*PeerConfig
}

func NewContext(suite abstract.Suite,
		random cipher.Stream, config *PeerConfig) *Context {

	return &Context{ suite, random, config}
}

func (c *Context) NextNonce() Nonce {
	return c.Suite.Secret().Pick(c.Random)
}

// Sign the message in the current context.
func (c *Context) Sign(m *Message) {
	self := c.Self()
	signature := anon.Sign(c.Suite, c.Random, m.Data,
			anon.Set{self.PubKey}, nil, 0, self.PrivKey)
	m.Signature = signature
}

// Verify the message against the source specified in the
// message itself.
func (c *Context) Verify(m *Message) error {
	key := anon.Set{c.Peers[m.Source].PubKey}
	_, err := anon.Verify(c.Suite, m.Data, key, nil, m.Signature)
	return err
}
