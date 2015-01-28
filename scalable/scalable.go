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
	cons protobuf.Constructors

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

	// second round trustee stuff
	shares map[uint32]abstract.Secret
	signatures []*TrusteeSignatureMessage

	// third round reporting of signatures
	signatureVector []*SignatureVectorMessage

	// fourth round, secrets finally released
	secretVector []abstract.Secret
}

func NewScalableSessionBase(context *Context,
		nonce Nonce) *ScalableSessionBase {

	cons := protobuf.Constructors {
		tSecret: func()interface{} { return context.Suite.Secret() },
		tNonce: func()interface{} { return context.Suite.Secret() },
		tPoint: func()interface{} { return context.Suite.Point() },
	}
	return &ScalableSessionBase {
		context,
		cons,
		nonce,
		nil,
		context.Suite.Secret(),
		context.Suite.Point(),
		nil,
		make([][]byte, context.N),
		new(poly.PriPoly),
		new(poly.PriShares),
		new(poly.PubPoly),
		nil,
		nil,
		nil,
		nil,
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
	Source, Index int
	Share abstract.Secret
	Commitment interface{} //poly.PubPoly
}

type TrusteeSignatureMessage struct {
	Trustee, Source, Index int
	//Signature []byte
}

func (s *ScalableSessionBase) DoTrusteeExchange(i,
		trustee int) (*TrusteeSignatureMessage, error) {

	conn, err := net.DialTimeout("tcp", s.Peers[trustee].Addr, timeout)
	if err != nil {
		return nil, err
	}

	// send session nonce
	announce := &NonceMessage{ s.Nonce }
	_, err = WritePrefix(conn, protobuf.Encode(announce))
	if err != nil {
		return nil, err
	}

	// send share to trustee
	message := &TrusteeShareMessage{
		s.Mine, i,
		s.sh_i.Share(i),
		s.p_i,
	}
	_, err = WritePrefix(conn, protobuf.Encode(message))
	if err != nil {
		return nil, err
	}

	// wait to get signature back
	reply := new(TrusteeSignatureMessage)
	if err := ReadOneTimeout(conn, reply, nil, time.Second); err != nil {
		return nil, err
	}
	conn.Close()
	return reply, nil
}


func (s *ScalableSessionBase) SendTrusteeShares(R int) error {
	// Seed with H(V_C_p, C_i)
	h := s.Suite.Hash()
	for _, C_p := range s.V_C_p {
		h.Write(C_p)
	}
	h.Write(s.C_i.Encode())
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
	results := make(chan *TrusteeSignatureMessage, R)

	for i, trustee := range selected {
		if trustee == s.Mine { continue }

		go func(i, trustee int) {
			reply, err := s.DoTrusteeExchange(i, trustee)
			if err != nil {
				fmt.Println("Exchange: " + err.Error())
				results <- nil
			}
			results <- reply
		}(i, trustee)
	}

	s.signatures = make([]*TrusteeSignatureMessage, R)
	nilCount := 0
	for i := 0; i < R-1; i++ {
		message := <- results
		if message == nil {
			nilCount++
			continue
		}
		s.signatures[message.Index] = message
	}
	return nil
}

func (s *ScalableSessionBase) HandleSigningRequests() error {
	timeout := time.After(time.Second * 5)

	results := make(chan *TrusteeShareMessage)
	s.shares = make(map[uint32]abstract.Secret)
Listen:
	for {
		select {
		case <- timeout:
			break Listen
		case conn := <- s.ConnChan:
			go func(conn net.Conn) {
				commitment := new(poly.PubPoly)
				commitment.Init(s.Suite, s.K, nil)

				message := new(TrusteeShareMessage)
				message.Share = s.Suite.Secret()
				message.Commitment = commitment

				err := ReadOne(conn, message, nil)
				if err != nil {
					results <- nil
					return
				}
				results <- message

				reply := &TrusteeSignatureMessage {
					s.Mine, message.Source, message.Index,
				}
				_, err = WritePrefix(conn, protobuf.Encode(reply))
				if err != nil {
					results <- nil
					return
				}
			}(conn)
		case message := <- results:
			key := uint32(message.Source << 16 | message.Index)
			s.shares[key] = message.Share
		}
	}
	fmt.Println("Done accepting signing requests.")
	fmt.Printf("Holding %d shares.\n", len(s.shares))
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

	incoming := make(chan net.Conn, context.N)
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

type SignatureVectorMessage struct {
	Source int
	Commit abstract.Point
	Signatures []*TrusteeSignatureMessage
}

func (s *ScalableSession) SendSignatureVector() error {
	message := protobuf.Encode(&SignatureVectorMessage{
		s.Mine, s.C_i, s.signatures,
	})
	_, err := WritePrefix(s.Conn, message)
	fmt.Println("Sent SignatureVector.")
	return err
}

func (s *ScalableSession) ReceiveSignatureVectorVector() error {
	message := new(SignatureVectorVectorMessage)
	if err := ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	s.signatureVector = message.Signatures
	fmt.Println("Got SignatureVectorVector.")
	return nil
}

type SecretMessage struct {
	Source int
	Secret abstract.Secret
}

func (s *ScalableSession) SendSecret() error {
	message := protobuf.Encode(&SecretMessage{
		s.Mine, s.s_i,
	})
	_, err := WritePrefix(s.Conn, message)
	fmt.Println("Sent Secret.")
	return err
}

func (s *ScalableSession) ReceiveSecretVector() error {
	message := new(SecretVectorMessage)
	if err := ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	s.secretVector = message.Secrets
	fmt.Println("Got secret vector.")
	return nil
}

func (s *ScalableSessionBase) CalculateTickets() error {
	for i := 0; i < s.N; i++ {
		h := s.Suite.Hash()
		for _, sig := range s.signatureVector {
			h.Write(protobuf.Encode(sig))
		}
		for _, secret := range s.secretVector {
			h.Write(secret.Encode())
		}
		buf := make([]byte, h.Size())
		binary.PutVarint(buf, int64(i))
		h.Write(buf)
		ticket := h.Sum(nil)
		fmt.Printf("%d: %s\n", i, string(ticket))
	}
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

	go s.HandleSigningRequests()
	s.GenerateTrusteeShares(s.K, s.N)
	if err := s.SendTrusteeShares(s.N); err != nil {
		panic("SendTrusteeShares: " + err.Error())
	}

	if err := s.SendSignatureVector(); err != nil {
		panic("SendSignatureVector: " + err.Error())
	}

	if err := s.ReceiveSignatureVectorVector(); err != nil {
		panic("ReceiveSignatureVectorVector: " + err.Error())
	}

	if err := s.SendSecret(); err != nil {
		panic("SendSecret: " + err.Error())
	}

	if err := s.ReceiveSecretVector(); err != nil {
		panic("ReceiveSecretVector: " + err.Error())
	}

	if err := s.CalculateTickets(); err != nil {
		panic("CalculateTickets: " + err.Error())
	}
}
