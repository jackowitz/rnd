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
		Context: context, R: R, Q: Q, cons: cons,
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
	s.s_i = s.Suite.Secret().Pick(s.Random)

	// Inner commitment (C_i = g^s_i).
	s.C_i = s.Suite.Point().Mul(nil, s.s_i)

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
	s.a_i = new(poly.PriPoly)
	s.a_i.Pick(s.Suite, s.Q, s.s_i, s.Random)

	// Generate a commitment to the polynomial, allowing shares
	// of the polynomial to be verified.
	s.p_i = new(poly.PubPoly)
	s.p_i.Commit(s.a_i, nil)

	// Produce the actual shares.
	s.sh_i = new(poly.PriShares)
	s.sh_i.Split(s.a_i, s.R)
}

// Perform the full request, response, verification cycle with
// a single trustee.
func (s *SessionBase) DoTrusteeExchange(shareIndex,
		trusteeIndex int, timeout time.Duration) (*TrusteeSignatureMessage, error) {

	// Form a short-lived connection to the trustee.
	addr := s.Peers[trusteeIndex].Addr
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	// Send the request off...
	message := &TrusteeShareMessage{
		s.Mine, shareIndex, s.sh_i.Share(shareIndex), s.p_i,
	}
	buf, _ := protobuf.Encode(message)
	_, err = prefix.WritePrefix(conn, buf)
	if err != nil {
		return nil, err
	}

	// ...and wait to get attestation back.
	reply := new(TrusteeSignatureMessage)
	if err := broadcaster.ReadOneTimeout(conn, reply, nil, timeout); err != nil {
		return nil, err
	}
	// Make sure the attestation is properly signed so we can later
	// prove to others that we followed the protocol.
	signature := reply.Signature
	reply.Signature = nil
	data, _ := protobuf.Encode(reply)
	if err := s.Verify(data, signature, reply.Trustee); err != nil {
		return nil, errors.New("EVERIFY")
	}
	reply.Signature = signature

	// Don't need this anymore.
	conn.Close()
	return reply, nil
}

// Find the set of trustees responsible for holding the secret
// corresponding to the provided commitment. Clients use this to
// initially find their trustees, and the leader may need it to
// locate the trustees later to recover shares.
func (s *SessionBase) findTrustees(C_i abstract.Point) []int {
	// Seed the selection with H(V_C_p, C_i), so the leader can
	// re-create the choice later if needed (and so anyone can
	// verify that the trustees were chosen properly).
	h := s.Suite.Hash()
	for _, C_p := range s.V_C_p {
		h.Write(C_p)
	}
	cib, _ := C_i.MarshalBinary()
	h.Write(cib)
	seedBytes := h.Sum(nil)

	// Go seems to require a fairly convoluted/ugly mechanism
	// for picking a random sub-slice. Oh well, it works...
	var seed int64
	buf := bytes.NewBuffer(seedBytes[:8])
	binary.Read(buf, binary.LittleEndian, &seed)
	trusteeRandom := rand.New(rand.NewSource(seed))
	return trusteeRandom.Perm(s.N)[:s.R]
}

// Perform the exchange with the full set of trustees. Since
// each request/signature exchange is independent of the others,
// we fire them all off in parallel and then wait for the replies
// (or a timeout).
func (s *SessionBase) SendTrusteeShares(timeout time.Duration) error {

	s.signatures = make([]*TrusteeSignatureMessage, s.R)
	results := make(chan *TrusteeSignatureMessage, s.R)
	expected := s.R

	trustees := s.findTrustees(s.C_i)
	for i, trustee := range trustees {
		// Possible we picked ourself to be a trustee. For now
		// we'll say that that's OK.
		if trustee == s.Mine {
			expected--
			reply := &TrusteeSignatureMessage {
				s.Mine, s.Mine, i, nil,
			}
			data, _ := protobuf.Encode(reply)
			signature := s.Sign(data)
			reply.Signature = signature
			s.signatures[i] = reply
			continue
		}

		// Sent off the requests, each in their own goroutine.
		go func(i, trustee int) {
			reply, err := s.DoTrusteeExchange(i, trustee, timeout)
			if err != nil {
				fmt.Println("Trustee Exchange: " + err.Error())
				results <- nil
			}
			results <- reply
		}(i, trustee)
	}

	// Wait to get signatures or errors back from all of the
	// trustees and make sure that at least Q of them were
	// successful.
	received := s.R - expected
	for i := 0; i < expected; i++ {
		message := <- results
		if message != nil {
			s.signatures[message.Index] = message
			received++
		}
	}
	if received < s.Q {
		return errors.New("ENOT_ENOUGH_TRUSTEES")
	}
	return nil
}

// Handle a single request to serve as a trustee for a share of
// a secret. Right now all requests are being served by the same
// goroutine, but it may make sense to parallelize them.
func (s *SessionBase) HandleSigningRequest(conn net.Conn) error {
	// Initialize the message. We could just as easily put a
	// PubPoly constructor into the protobuf map...
	commitment := new(poly.PubPoly)
	commitment.Init(s.Suite, s.K, nil)

	message := new(TrusteeShareMessage)
	message.Share = s.Suite.Secret()
	message.Commitment = commitment

	// Read the incoming request.
	err := broadcaster.ReadOne(conn, message, nil)
	if err != nil {
		return err
	}

	// Check the share against the commitment. We only want provide
	// attestation if we know it's a valid share we're holding.
	commitment, ok := message.Commitment.(*poly.PubPoly)
	if commitment == nil || !ok {
		return errors.New("Commitment isn't a *poly.PubPoly.")
	}

	// Make sure this commitment matches the earlier one, in case a
	// client tries to get sneaky and swap out their secret here.
	h := s.Suite.Hash()
	hbuf, _ := commitment.SecretCommit().MarshalBinary()
	h.Write(hbuf)
	outer := h.Sum(nil)
	if !bytes.Equal(outer, s.V_C_p[message.Source]) {
		return errors.New("Inner commit doesn't match outer.")
	}

	// Now that we know the polynomial commitment is valid, check the
	// share against it.
	if !commitment.Check(message.Index, message.Share) {
		return errors.New("Share doesn't check against commitment.")
	}

	// Store the share away so we can produce it later, if needed.
	key := uint32(message.Source << 16 | message.Index)
	s.shares[key] = message.Share

	// Reply with our attestation that we are holding this
	// particular share for the requesting client.
	reply := &TrusteeSignatureMessage {
		s.Mine, message.Source, message.Index, nil,
	}
	data, err := protobuf.Encode(reply)
	signature := s.Sign(data)
	reply.Signature = signature

	buf, _ := protobuf.Encode(reply)
	_, err = prefix.WritePrefix(conn, buf)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Loop to multiplex incoming requests to serve as a trustee.
// Delegates the actual work.
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
	return nil
}

// Make sure that there are enough attestations, that the signatures
// in the attestations are valid and that the trustees were chosen
// properly.
func (s *SessionBase) validateAttestation(message *SignatureVectorMessage) error {
	trustees := s.findTrustees(message.Commit)
	attestations := 0

	for i, reply := range message.Signatures {
		// First check that the trustee provided an attestation and
		// that they were chosen properly.
		if reply == nil || reply.Trustee != trustees[i] {
			continue
		}
		// Validate the signature on the attestation.
		signature := reply.Signature
		reply.Signature = nil
		data, _ := protobuf.Encode(reply)
		reply.Signature = signature
		if err := s.Verify(data, signature, reply.Trustee); err != nil {
			continue
		}
		attestations++
	}
	// Make sure that at least Q of the attestations checked out.
	if attestations < s.Q {
		return errors.New("Not enough valid trustee attestations.")
	}
	return nil
}

// Perform local calculations to determine the "winning" lottery
// tickets. In this case, we just do the hashing and then dump
// each client's "ticket" to the console.
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
