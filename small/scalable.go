package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/protobuf"
)

// Common to both the leader and the others.
type ScalableSessionBase struct {
	*Context
	Nonce Nonce
	ConnChan <-chan net.Conn

	// First round commits.
	s_i abstract.Secret
	C_i abstract.Point
	C_i_p []byte
	V_C_p [][]byte

	a_i *poly.PriPoly
	sh_i *poly.PriShares
	p_i *poly.PubPoly
}

func NewScalableSessionBase(context *Context,
		nonce Nonce) *ScalableSessionBase {

	return &ScalableSessionBase {
		context,
		nonce,
		nil,
		context.Suite.Secret(),
		context.Suite.Point(),
		nil,
		make([][]byte, context.N),
		new(poly.PriPoly),
		new(poly.PriShares),
		new(poly.PubPoly),
	}
}

func (s *ScalableSessionBase) GenerateInitialShares() {
	s.s_i.Pick(s.Random)
	s.C_i.Mul(nil, s.s_i)

	h := s.Suite.Hash()
	h.Write(s.C_i.Encode())
	s.C_i_p = h.Sum(nil)
}

func (s *ScalableSessionBase) GenerateTrusteeShares(Q, R int) {
	s.a_i.Pick(s.Suite, Q, s.s_i, s.Random)
	s.sh_i.Split(s.a_i, R)
	s.p_i.Commit(s.a_i, nil)
}

type TrusteeShareMessage struct {
	Source int
	Share abstract.Secret
	Commitment interface{} //poly.PubPoly
}

func (s *ScalableSessionBase) SendTrusteeShares(R int) error {
	// Seed with H(V_C_p, C_i)
	h := s.Suite.Hash()
	for _, C_p := range s.V_C_p {
		h.Write(C_p)
	}
	h.Write(protobuf.Encode(s.C_i))
	seedBytes := h.Sum(nil)

	// Convoluted mechanism here... all we're trying to do is
	// pick R out of N elements; Go doesn't make it easy!
	// XXX paper says hash functions, but then we can end up
	// with single trustees getting multiple of our shares;
	// is that desirable or undesirable?
	var seed int64
	buf := bytes.NewBuffer(seedBytes[:8])
	binary.Read(buf, binary.LittleEndian, &seed)
	trusteeRandom := rand.New(rand.NewSource(seed))
	selected := trusteeRandom.Perm(s.N)[:R]

	// Send the share and C_i to each selected trustee.
	for i, trustee := range selected {
		if trustee == s.Mine { continue }

		conn, err := net.DialTimeout("tcp", s.Peers[trustee].Addr, timeout)
		if err != nil {
			format := "Unable to connect to trustee at %s"
			panic(fmt.Sprintf(format, s.Peers[trustee].Addr))
		}

		// send session nonce
		announce := &NonceMessage{ s.Nonce }
		_, err = WritePrefix(conn, protobuf.Encode(announce))
		if err != nil {
			panic("announcement: " + err.Error())
		}

		// send share to trustee
		message := &TrusteeShareMessage{
			s.Mine,
			s.sh_i.Share(i),
			s.p_i,
		}
		_, err = WritePrefix(conn, protobuf.Encode(message))
		if err != nil {
			panic("announcement: " + err.Error())
		}
	}

	return nil
}

func (s *ScalableSessionBase) HandleSigningRequests() error {
	timeout := time.After(time.Second * 5)

	for {
		select {
		case <-timeout:
			break
		case conn := <- s.ConnChan:
			commitment := new(poly.PubPoly)
			commitment.Init(s.Suite, s.K, nil)

			message := new(TrusteeShareMessage)
			message.Share = s.Suite.Secret()
			message.Commitment = commitment

			err := ReadOne(conn, message, nil)
			if err != nil {
				panic("HandleSigningRequests :" + err.Error())
			}
			break
		}
	}
	return nil
}

// Specific to just the others.
type ScalableSession struct {
	*ScalableSessionBase

	Conn net.Conn
}

func NewScalableSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-net.Conn {

	scalable := &ScalableSession {
		NewScalableSessionBase(context, nonce),
		nil,
	}

	incoming := make(chan net.Conn)
	go scalable.Start(incoming, replyConn, done)

	return incoming
}

func (s *ScalableSession) Start(connChan <-chan net.Conn,
		replyConn net.Conn, close chan<- Nonce) {

	// Store connection channel away for later.
	s.ConnChan = connChan

	// Get our connection to the leader.
	s.Conn = <- connChan

	fmt.Println("Started " + s.Nonce.String())
	s.RunLottery()
}

type HashCommitMessage struct {
	Source int
	Commit []byte
}

func (s *ScalableSession) SendHashCommit() error {
	message := protobuf.Encode(&HashCommitMessage{ s.Mine, s.C_i_p })
	_, err := WritePrefix(s.Conn, message)
	return err
}

func (s *ScalableSession) ReceiveHashCommitVector() error {
	message := new(HashCommitVectorMessage)
	if err := ReadOne(s.Conn, message, nil); err != nil {
		return err
	}
	s.V_C_p = message.Commits
	return nil
}

func (s *ScalableSession) RunLottery() {
	s.GenerateInitialShares()

	if err := s.SendHashCommit(); err != nil {
		panic("SendHashCommit: " + err.Error())
	}

	if err := s.ReceiveHashCommitVector(); err != nil {
		panic("ReceiveHashCommitVector: " + err.Error())
	}

	s.GenerateTrusteeShares(s.K, s.N)
	if err := s.SendTrusteeShares(s.N); err != nil {
		panic("SendTrusteeShares: " + err.Error())
	}

	s.HandleSigningRequests()
}
