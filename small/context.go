package main

import (
	"crypto/cipher"
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

func (p *PeerConfig) IsMine(i int) bool {
	return i == p.Mine
}

func (p *PeerConfig) Self() *Peer {
	return &p.Peers[p.Mine]
}

func NewPeerConfig(suite abstract.Suite, random cipher.Stream,
		mine, n, k int, hosts []string) *PeerConfig {

	peers := make([]Peer, n)
	for i := range peers {
		x := suite.Secret().Pick(random)
		X := suite.Point().Mul(nil, x)
		peers[i] = Peer{ i, hosts[i], x, X }
	}
	return &PeerConfig{ peers, mine, n, k }
}

type Context struct {
	Suite abstract.Suite
	Random cipher.Stream

	*PeerConfig
}

func NewContext(suite abstract.Suite, random cipher.Stream,
		config *PeerConfig) *Context {

	return &Context{ suite, random, config}
}

// Sign the message in the current context.
func (c *Context) Sign(message []byte) []byte {
	self := c.Self()
	return anon.Sign(c.Suite, c.Random, message,
			anon.Set{self.PubKey}, nil, 0, self.PrivKey)
}

// Verify the message against the source specified in the
// message itself.
func (c *Context) Verify(message, signature []byte, server int) error {
	key := anon.Set{c.Peers[server].PubKey}
	_, err := anon.Verify(c.Suite, message, key, nil, signature)
	return err
}
