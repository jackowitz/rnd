package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/protobuf"
	"reflect"
	"rnd/broadcaster"
	"rnd/context"
	"rnd/prefix"
)

// Common to both the leader and the others.
type SessionBase struct {
	*context.Context
	R, Q int
	cons protobuf.Constructors

	// The nonce identifying this session.
	Nonce Nonce

	// Channel for receiving incoming connections; used
	// for both the session initiation by the leader and
	// for trustee requests later in the protocol.
	ConnChan <-chan net.Conn

	s_i abstract.Secret		// The secret.
	C_i abstract.Point		// The commitment to the secret.
	C_i_p []byte			// The outer commitment.

	V_C_p [][]byte			// Vector of outer commitments.

	a_i *poly.PriPoly		// Polynomial encoding the secret.
	sh_i *poly.PriShares	// Shares of the polynomial for trustees.
	p_i *poly.PubPoly		// Commitment to the polynomial.

	shares map[uint32]abstract.Secret		// Share's we're holding.
	signatures []*TrusteeSignatureMessage	// Signatures of trustees that
											// are holding our shares.

	signatureVector []*SignatureVectorMessage	// Everybody's signatures
												// from their trustees.

	secretVector []abstract.Secret	// Everybody's secrets.
}

func NewSessionBase(context *context.Context, R, Q int) *SessionBase {

	// Constructors for use with protobuf stuff.
	var cons protobuf.Constructors =
		func(t reflect.Type) interface{} {
			switch t {
			case tSecret:
				return context.Suite.Secret()
			case tNonce:
				return context.Suite.Secret()
			case tPoint:
				return context.Suite.Point()
			default:
				return nil
			}
		}

	return &SessionBase {
		context,
		R, Q,
		cons,
		nil,
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

// Start up any core session stuff, namely listening for requests
// to be a trustee as these will come to both the leader and
// regular clients.
// XXX: Right now trustee requests come in on the same port as the
// initial connection from the leader, using the heuristic that the
// first connection will be the leader.
func (s *SessionBase) Start() {
	server, err := net.Listen("tcp", s.Self().Addr)
	if err != nil {
		panic("Listen: " + err.Error())
	}
	incoming := make(chan net.Conn, s.N)
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				continue
			}
			incoming <- conn
		}
	}()
	s.ConnChan = incoming
}

// Pick a random secret and generate the inner and outer
// commitments to that secret.
func (s *SessionBase) GenerateInitialShares() {
	// The secret (s_i).
	s.s_i.Pick(s.Random)

	// Inner commitment (C_i = g^s_i).
	s.C_i.Mul(nil, s.s_i)

	// Outer commitment (C_i_prime = H(C_i)).
	h := s.Suite.Hash()
	buf, _ := s.C_i.MarshalBinary()
	h.Write(buf)
	s.C_i_p = h.Sum(nil)
}

// Split the secret into R shares, Q of which are needed to
// reconstruct the secret.
func (s *SessionBase) GenerateTrusteeShares() {
	// Pick a polynomial, with the secret as p(0).
	s.a_i.Pick(s.Suite, s.Q, s.s_i, s.Random)

	// Generate a commitment to the polynomial, allowing shares
	// of the polynomial to be verified.
	s.p_i.Commit(s.a_i, nil)

	// Produce the actual shares.
	s.sh_i.Split(s.a_i, s.R)
}

func (s *SessionBase) DoTrusteeExchange(i,
		trustee int) (*TrusteeSignatureMessage, error) {

	// Connect to the trustee.
	conn, err := net.DialTimeout("tcp", s.Peers[trustee].Addr, timeout)
	if err != nil {
		return nil, err
	}

	// send share to trustee
	message := &TrusteeShareMessage{
		s.Mine, i,
		s.sh_i.Share(i),
		s.p_i,
	}
	buf, _ := protobuf.Encode(message)
	_, err = prefix.WritePrefix(conn, buf)
	if err != nil {
		return nil, err
	}

	// wait to get signature back
	reply := new(TrusteeSignatureMessage)
	if err := broadcaster.ReadOneTimeout(conn, reply, nil, 3 * time.Second); err != nil {
		return nil, err
	}
	conn.Close()
	return reply, nil
}

// Find the set of trustees responsible for holding the secret
// corresponding to the provided commitment.
func (s *SessionBase) findTrustees(C_i abstract.Point) []int {
	// Seed with H(V_C_p, C_i)
	h := s.Suite.Hash()
	for _, C_p := range s.V_C_p {
		h.Write(C_p)
	}
	cib, _ := C_i.MarshalBinary()
	h.Write(cib)
	seedBytes := h.Sum(nil)

	// Convoluted mechanism here... all we're trying to do is
	// pick R out of N elements!
	var seed int64
	buf := bytes.NewBuffer(seedBytes[:8])
	binary.Read(buf, binary.LittleEndian, &seed)
	trusteeRandom := rand.New(rand.NewSource(seed))
	return trusteeRandom.Perm(s.N)[:s.R]
}

func (s *SessionBase) SendTrusteeShares() error {

	// Send the share and C_i to each selected trustee.
	// Fire off all of the requests in parallel.
	results := make(chan *TrusteeSignatureMessage, s.R)
	expected := s.R

	trustees := s.findTrustees(s.C_i)
	for i, trustee := range trustees {
		if trustee == s.Mine {
			expected--
			continue
		}

		go func(i, trustee int) {
			reply, err := s.DoTrusteeExchange(i, trustee)
			if err != nil {
				fmt.Println("Trustee Exchange: " + err.Error())
				results <- nil
			}
			results <- reply
		}(i, trustee)
	}

	// Wait to get the signatures back for at least Q.
	s.signatures = make([]*TrusteeSignatureMessage, s.R)
	received := s.R - expected
	for i := 0; i < expected; i++ {
		message := <- results
		if message != nil {
			s.signatures[message.Index] = message
			received++
		}
	}
	if received < s.Q {
		return errors.New("ENOT_ENOUGH_SIGS")
	}
	return nil
}

func (s *SessionBase) HandleSigningRequest(conn net.Conn) error {
	commitment := new(poly.PubPoly)
	commitment.Init(s.Suite, s.K, nil)

	message := new(TrusteeShareMessage)
	message.Share = s.Suite.Secret()
	message.Commitment = commitment

	err := broadcaster.ReadOne(conn, message, nil)
	if err != nil {
		return err
	}

	reply := &TrusteeSignatureMessage {
		s.Mine, message.Source, message.Index,
	}
	buf, _ := protobuf.Encode(reply)
	_, err = prefix.WritePrefix(conn, buf)
	if err != nil {
		return err
	}
	conn.Close()

	fmt.Printf("Holding share %d for %d.\n", message.Index, message.Source)
	key := uint32(message.Source << 16 | message.Index)
	s.shares[key] = message.Share
	return nil
}

func (s *SessionBase) HandleSigningRequests() error {
	timeout := time.After(time.Second * 5)

	s.shares = make(map[uint32]abstract.Secret)
Listen:
	for {
		select {
		case <- timeout:
			break Listen
		case conn := <- s.ConnChan:
			s.HandleSigningRequest(conn)
		}
	}
	fmt.Println("Done accepting signing requests.")
	fmt.Printf("Holding %d shares.\n", len(s.shares))
	return nil
}

// Perform local calculations needed to determine the
// "winning" lottery tickets.
func (s *SessionBase) CalculateTickets() error {
	for i := 0; i < s.N; i++ {
		h := s.Suite.Hash()
		for _, sig := range s.signatureVector {
			buf, _ := protobuf.Encode(sig)
			h.Write(buf)
		}
		for _, secret := range s.secretVector {
			buf, _ := secret.MarshalBinary()
			h.Write(buf)
		}
		buf := make([]byte, h.Size())
		binary.PutVarint(buf, int64(i))
		h.Write(buf)
		ticket := h.Sum(nil)
		fmt.Printf("%d: %s\n", i, string(ticket))
	}
	return nil
}
