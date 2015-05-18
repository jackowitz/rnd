package context

import (
	"bufio"
	"crypto/cipher"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
	"os"
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

func LocalHosts(n int) []string {
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("localhost:%d", 8080+i)
	}
	return hosts
}

func LoadHostsFile(path string, n int) ([]string, error) {
	hosts := make([]string, n)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(file)
	for i := range hosts {
		host, _, err := reader.ReadLine()
		if err != nil {
			return nil, err
		}
		hosts[i] = string(host)
	}
	return hosts, nil
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
