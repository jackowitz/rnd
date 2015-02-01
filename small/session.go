package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/protobuf"
	"rnd/broadcaster"
	"rnd/prefix"
	"rnd/stopwatch"
)

type Session struct {
	*Context
	*broadcaster.Broadcaster

	Nonce Nonce
	cons protobuf.Constructors

	r_i abstract.Secret
	a_i *poly.PriPoly
	s_i *poly.PriShares
	p_i *poly.PubPoly

	shares []*poly.PriShares
	commitments []*poly.PubPoly
}

// Starts a new session in the given context. The session is identified
// by the provided nonce and produces a single random value.
// Returns immediately with a channel on which subsequent connections
// to the session are delivered but spawns a new goroutine to run
// the actual session.
func NewSession(context *Context, nonce Nonce, replyConn net.Conn,
		done chan<- Nonce) chan <- net.Conn {

	conns := make([]net.Conn, context.N)
	broadcaster := broadcaster.NewBroadcaster(conns)

	cons := protobuf.Constructors{
		tSecret: func()interface{} { return context.Suite.Secret() },
		tNonce: func()interface{} { return context.Suite.Secret() },
		tPoint: func()interface{} { return context.Suite.Point() },
	}

	session := &Session{
		context,
		broadcaster,
		nonce,
		cons,
		context.Suite.Secret(),
		new(poly.PriPoly),
		new(poly.PriShares),
		new(poly.PubPoly),
		make([]*poly.PriShares, context.N),
		make([]*poly.PubPoly, context.N),
	}

	for i := range session.shares {
		session.shares[i] = new(poly.PriShares)
		session.shares[i].Empty(session.Suite, session.K, session.N)
	}

	incoming := make(chan net.Conn)
	go session.Start(incoming, replyConn, done)

	return incoming
}

func (s *Session) GenerateRandom() (abstract.Secret, *stopwatch.Stopwatch) {

	stopwatch := stopwatch.NewStopwatch()

	stopwatch.Start()
	s.GenerateInitialShares()
	stopwatch.Stop("PickSplitCommit")

	stopwatch.Start()
	if err := s.SendShareCommitMessages(); err != nil {
		panic("SendShareCommitMessages: " + err.Error())
	}
	stopwatch.Stop("SendCommits")

	stopwatch.Start()
	status := SUCCESS
	if err := s.ReceiveShareCommitMessages(); err != nil {
		panic("ReceiveShareCommitMessages: " + err.Error())
		status = FAILURE
	}
	stopwatch.Stop("ReceiveCommits")

	stopwatch.Start()
	if err := s.SendStatusMessages(status); err != nil {
		panic("SendStatusMessages: " + err.Error())
	}
	stopwatch.Stop("SendStatus")

	stopwatch.Start()
	if err := s.ReceiveStatusMessages(); err != nil {
		panic("ReceiveStatusMessages: " + err.Error())
	}
	stopwatch.Stop("ReceiveStatus")

	stopwatch.Start()
	if err := s.SendShareMessages(); err != nil {
		panic("SendShareMessages: " + err.Error())
	}
	stopwatch.Stop("SendShares")

	stopwatch.Start()
	if err := s.ReceiveShareMessages(); err != nil {
		panic("ReceiveShareMessages: " + err.Error())
	}
	stopwatch.Stop("ReceiveShares")

	stopwatch.Start()
	value, err :=  s.CombineShares()
	if err != nil {
		panic("CombineShares: " + err.Error())
	}
	stopwatch.Stop("CombineShares")

	return value, stopwatch
}

const timeout = 3 * time.Second

func (s *Session) Start(connChan <-chan net.Conn,
		replyConn net.Conn, close chan<- Nonce) {

	// Connect to all servers with ID > Mine.
	for i := s.Mine + 1; i < s.N; i++ {
		conn, err := net.DialTimeout("tcp", s.Peers[i].Addr, timeout)
		if err != nil {
			format := "Unable to connect to server at %s"
			panic(fmt.Sprintf(format, s.Peers[i].Addr))
		}
		// Send the session Nonce.
		buf := s.Nonce.Encode()
		if _, err := prefix.WritePrefix(conn, buf); err != nil {
			panic("Writing Nonce: " + err.Error())
		}
		// And identify ourself.
		n := binary.PutVarint(buf, int64(s.Mine))
		if _, err := prefix.WritePrefix(conn, buf[:n]); err != nil {
			panic("Writing ID: " + err.Error())
		}
		s.Conns[i] = conn
	}

	// Wait for all servers with ID < Mine.
	for i := 0; i < s.Mine; i++ {
		conn := <- connChan
		buf, err := prefix.ReadPrefix(conn)
		if err != nil {
			panic("ReadID: " + err.Error())
		}
		id, n := binary.Varint(buf)
		if n < 1 {
			panic("DecodeID")
		}
		s.Conns[int(id)] = conn
	}

	// No more connections for this session.
	close <- s.Nonce

	// Everyone's all wired up, start the protocol.
	value, stopwatch := s.GenerateRandom()

	// Send value back to the requester.
	if replyConn != nil {
		if _, err := replyConn.Write(value.Encode()); err != nil {
			panic("Writing Reply: " + err.Error())
		}
		if err := replyConn.Close(); err != nil {
			panic("Closing ReplyConn: " + err.Error())
		}
	}

	if debug {
		format := "[%d, %d] %s\n%s"
		fmt.Printf(format, s.N, s.K, value.String(), stopwatch)
	}
}

// Generates all of the values that we need to contribute to the
// protocol. Also stows away the shares that we need to "distribute"
// to ourself.
func (s *Session) GenerateInitialShares() {
	s.r_i.Pick(s.Random)
	s.a_i.Pick(s.Suite, s.K, s.r_i, s.Random)
	s.s_i.Split(s.a_i, s.N)
	s.p_i.Commit(s.a_i, nil)

	s.shares[s.Mine] = s.s_i
	s.commitments[s.Mine] = s.p_i
}

type ShareCommitMessage struct {
	Nonce Nonce
	Index, Source int
	Share abstract.Secret
	Commitment interface{} // *poly.PubPoly
	Signature []byte
}

func (s *Session) SendShareCommitMessages() error {
	return s.Broadcast(func (i int) interface{} {
		message := &ShareCommitMessage{ s.Nonce, i,
				s.Mine, s.s_i.Share(i), s.p_i, nil }
		signature := s.Sign(protobuf.Encode(message))
		message.Signature = signature
		return message
	})
}

// Tries to receive a ShareCommitMessage from all N peers. If we
// get fewer than N, we error out, since we want the initial shares
// from everybody, not just threshold K.
func (s *Session) ReceiveShareCommitMessages() error {

	results := s.ReadAll(func() interface{} {
		commitment := new(poly.PubPoly)
		commitment.Init(s.Suite, s.K, nil)

		message := new(ShareCommitMessage)
		message.Commitment = commitment
		return message
	}, s.cons)

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*ShareCommitMessage)
		if message == nil || !ok {
			return errors.New("ERECV")
		}

		// Make sure that the share is actually intended for us.
		if message.Index != s.Mine {
			return errors.New("ENOT_MINE")
		}

		// Verify the signature to prevent both spoofing and
		// replay attacks.
		signature := message.Signature
		message.Signature = nil

		data := protobuf.Encode(message)
		err := s.Verify(data, signature, message.Source)
		if err != nil {
			return errors.New("EVERIFY")
		}

		// Check that the share is valid for the included commitment.
		// Store the commitment away for checking the share vectors
		// we get later against it later.
		commitment, ok := message.Commitment.(*poly.PubPoly)
		if commitment == nil || !ok {
			return errors.New("ECONVERT")
		}
		if !commitment.Check(message.Index, message.Share) {
			return errors.New("ECHECK")
		}
		source := message.Source
		s.shares[source].SetShare(message.Index, message.Share)
		s.commitments[source] = message.Commitment.(*poly.PubPoly)
	}
	return nil
}

type Status int
const (
	SUCCESS Status = iota
	FAILURE
)

type StatusMessage struct {
	Nonce Nonce
	Source int
	Status Status
	Signature []byte
}

func (s *Session) SendStatusMessages(status Status) error {
	message := &StatusMessage{ s.Nonce, s.Mine, status, nil }
	signature := s.Sign(protobuf.Encode(message))
	message.Signature = signature
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

// Wait to get a SUCCESS status message from everybody
// before continuing on to release our shares.
func (s *Session) ReceiveStatusMessages() error {
	results := s.ReadAll(func() interface{} {
		return new(StatusMessage)
	}, s.cons)

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*StatusMessage)
		if message == nil || !ok {
			return errors.New("ERECV")
		}

		// No spoofing SUCCESS messages here!
		signature := message.Signature
		message.Signature = nil

		data := protobuf.Encode(message)
		err := s.Verify(data, signature, message.Source)
		if err != nil {
			return errors.New("EVERIFY")
		}

		// Make sure it's actually SUCCESS.
		if message.Status != SUCCESS {
			return errors.New("EFAIL")
		}
	}
	return nil
}

// Contains the normal message header of Nonce and Source,
// plus a vector of all of the shares that belong to us.
// Signature is over the complete contents of the message.
type ShareMessage struct {
	Nonce Nonce
	Source int

	Shares []abstract.Secret
	Signature []byte
}

func (s *Session) SendShareMessages() error {

	// Flatten all of our shares for each secret into a
	// single vector to broadcast to everyone else.
	shares := make([]abstract.Secret, s.N)
	for i, share := range s.shares {
		shares[i] = share.Share(s.Mine)
	}

	// Sign the message and send it out.
	message := &ShareMessage{ s.Nonce, s.Mine, shares, nil }
	signature := s.Sign(protobuf.Encode(message))
	message.Signature = signature
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

// Receive at least K (including our own) vectors of shares
// of secrets. This is guaranteed to be enough to allow us
// to reconstruct everyone's original input values. See inline
// comment for more details.
func (s *Session) ReceiveShareMessages() error {

	results := s.ReadAll(func() interface{} {
		return new(ShareMessage)
	}, s.cons)

	earlyOut := true
	received := 1
	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*ShareMessage)
		if message == nil || !ok {
			return errors.New("ERECV")
		}

		// Make sure that it's signed by the party sending
		// the shares TO US (not the original owner).
		signature := message.Signature
		message.Signature = nil

		data := protobuf.Encode(message)
		err := s.Verify(data, signature, message.Source)
		if err != nil {
			return errors.New("EVERIFY")
		}

		// Blindly record the share; we'll worry about checking
		// it for correctness later.
		source := message.Source
		for i, share := range message.Shares {
			s.shares[i].SetShare(source, share)
		}
		received += 1

		// Try to take the early out of recovering the secret
		// from the first K shares that we get. Since we have
		// commitments to the secrets, we'll know whether the
		// recovered secret is correct or not. If it is, then
		// great, we can skip the expensive checking of shares;
		// otherwise we fall back to the slow path of checking
		// and then discarding any shares that don't make the cut.
		if earlyOut && received == s.K {
			if err := s.TryRecover(); err != nil {
				s.PruneShares()
			} else {
				fmt.Println("Taking the early out.")
				break
			}
		}

		// Now check that all shares in the vector are in
		// line with the original commitment polynomial
		// sent to us by the OWNER of the share in the first
		// step of the protocol.
		if !earlyOut || received > s.K {
			source := message.Source
			for i, share := range message.Shares {
				if !s.commitments[i].Check(source, share) {
					return errors.New("ECHECK")
				}
				s.shares[i].SetShare(source, share)
			}
		}
	}
	return nil
}

// We call this after getting the first K shares, regardless
// of whether the check out or not. Recovering the secret
// blindly and then checking against the commitment should be
// much faster than checking the shares. It can, of course,
// fail if someone sent a bad share.
func (s *Session) TryRecover() error {
	for i := range s.shares {
		recovered := s.shares[i].Secret()
		check := s.Suite.Point().Mul(nil, recovered)
		commitment := s.commitments[i].SecretCommit()
		if !check.Equal(commitment) {
			return errors.New("EBAD_SECRET")
		}
	}
	return nil
}

// If we tried to take the early out after the first K
// shares but failed because someone sent a bad share,
// then we need to go back and check all shares we got and
// remove any bad ones, so we can successfully recover later.
func (s *Session) PruneShares() {
	for i := range s.shares {
		for j := 0; j < s.N; j++ {
			share := s.shares[i].Share(j)
			if share != nil {
				if !s.commitments[i].Check(j, share) {
					s.shares[i].SetShare(j, nil)
				}
			}
		}
	}
}

// XOR all the individual secrets together to produce the final
// random value incorporating all clients' secrets. We may panic
// if we didn't get enough good shares, but this goes against our
// assumptions anyway.
func (s *Session) CombineShares() (abstract.Secret, error) {
	result := make([]byte, s.Suite.SecretLen())
	for i := range s.shares {
		recovered := s.shares[i].Secret()
		bytes := recovered.Encode()
		for i := 0; i < s.Suite.SecretLen(); i++ {
			result[i] ^= bytes[i]
		}
	}
	value := s.Suite.Secret()
	if err := value.Decode(result); err != nil {
		return nil, err
	}
	return value, nil
}
