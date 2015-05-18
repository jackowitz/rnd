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
	"github.com/dedis/protobuf"
	"reflect"
	"rnd/broadcaster"
	"rnd/context"
	"rnd/prefix"
)

// Common to both the leader and the others.
type SessionBase struct {
	*context.Context
	cons protobuf.Constructors

	// The nonce identifying this session.
	Nonce Nonce

	// Channel for receiving incoming connections; used
	// for both the session initiation by the leader and
	// for trustee requests later in the protocol.
	ConnChan <-chan net.Conn

	// Protocol Step 1:
	s_i abstract.Secret		// The secret.
	C_i abstract.Point		// The commitment to the secret.
	C_i_p []byte			// The outer commitment.

	// Protocol Step 2 & 3:
	V_C_p [][]byte			// Vector of outer commitments.

	// Protocol Step 4:
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

func NewSessionBase(context *context.Context) *SessionBase {

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

// Generates all of the values we need for Step 1, namely
// the secret and the inner and outer commitments.
func (s *SessionBase) GenerateInitialShares() {
	// The secret.
	s.s_i.Pick(s.Random)

	// Inner commitment.
	s.C_i.Mul(nil, s.s_i)

	// Outer commitment.
	h := s.Suite.Hash()
	buf, _ := s.C_i.MarshalBinary()
	h.Write(buf)
	s.C_i_p = h.Sum(nil)
}

func (s *SessionBase) GenerateTrusteeShares(Q, R int) {
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

func (s *SessionBase) DoTrusteeExchange(i,
		trustee int) (*TrusteeSignatureMessage, error) {

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


func (s *SessionBase) SendTrusteeShares(R int) error {
	// Seed with H(V_C_p, C_i)
	h := s.Suite.Hash()
	for _, C_p := range s.V_C_p {
		h.Write(C_p)
	}
	cib, _ := s.C_i.MarshalBinary()
	h.Write(cib)
	seedBytes := h.Sum(nil)

	// Convoluted mechanism here... all we're trying to do is
	// pick R out of N elements!
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
				fmt.Println("Trustee Exchange: " + err.Error())
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

func (s *SessionBase) HandleSigningRequests() error {
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

				err := broadcaster.ReadOne(conn, message, nil)
				if err != nil {
					fmt.Println(err.Error())
					results <- nil
					return
				}
				results <- message

				reply := &TrusteeSignatureMessage {
					s.Mine, message.Source, message.Index,
				}
				buf, _ := protobuf.Encode(reply)
				_, err = prefix.WritePrefix(conn, buf)
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
