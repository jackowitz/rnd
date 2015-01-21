package main

import (
	"errors"
	"fmt"
	"net"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/protobuf"
	"rnd_tcp/stopwatch"
)

type SmallSession struct {
	*Context
	*Broadcaster

	Nonce Nonce

	r_i abstract.Secret
	a_i *poly.PriPoly
	s_i *poly.PriShares
	p_i *poly.PubPoly

	shares []*poly.PriShares
	commitments []*poly.PubPoly
}

func NewSmallSession(context *Context, nonce Nonce, replyConn net.Conn,
		done chan<- Nonce) chan <- net.Conn {

	conns := make([]net.Conn, context.N)
	broadcaster := &Broadcaster{ context, conns }

	session := &SmallSession{
		context,
		broadcaster,
		nonce,
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

// Starts a new session in the given context. The session is identified
// by the provided nonce and produces a single random value.
// Returns immediately with a channel on which subsequent connections
// to the session are delivered but spawns a new goroutine to run
// the actual session.
func (s *SmallSession) GenerateRandom() (abstract.Secret, *stopwatch.Stopwatch) {

	// Record performance/debug timings.
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

	// XOR all the individual secrets together
	stopwatch.Start()
	value, err :=  s.CombineShares()
	if err != nil {
		panic("CombineShares: " + err.Error())
	}
	stopwatch.Stop("CombineShares")

	// XXX: this approach is group-dependent, maybe
	// just want to return a []byte
	return value, stopwatch
}

const timeout = 3*time.Second

func (s *SmallSession) Start(connChan <-chan net.Conn,
		replyConn net.Conn, close chan<- Nonce) {

	// Connect to all servers with ID > Mine.
	for i := s.Mine + 1; i < s.N; i++ {
		conn, err := net.DialTimeout("tcp", s.Peers[i].Addr, timeout)
		if err != nil {
			format := "Unable to connect to server at %s"
			panic(fmt.Sprintf(format, s.Peers[i].Addr))
		}
		buf := protobuf.Encode(&NonceMessage{ s.Nonce })
		if _, err := WritePrefix(conn, buf); err != nil {
			panic("Writing Nonce: " + err.Error())
		}
		s.Conns[i] = conn
	}

	// Wait for all servers with ID < Mine.
	for i := 0; i < s.Mine; i++ {
		s.Conns[i] = <- connChan
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

	// Dump any stats we may want.
	if debug {
		format := "[%d, %d] Times: %s\n"
		fmt.Printf(format, s.N, s.K, stopwatch)
		fmt.Printf("Value: %s\n", value.String())
	}
}

// Generates all of the values that we need to contribute to the
// protocol. Also stows away the shares that we need to "distribute"
// to ourself.
func (s *SmallSession) GenerateInitialShares() {
	s.r_i.Pick(s.Random)
	s.a_i.Pick(s.Suite, s.K, s.r_i, s.Random)
	s.s_i.Split(s.a_i, s.N)
	s.p_i.Commit(s.a_i, nil)

	s.shares[s.Mine] = s.s_i
	s.commitments[s.Mine] = s.p_i
}

type MessageType int
const (
	MSG_ANNOUNCE MessageType = iota
	MSG_SHARE_COMMIT
	MSG_STATUS
	MSG_SHARE
)

type ShareCommitMessage struct {
	Nonce Nonce
	Index, Source int
	Share abstract.Secret
	Commitment interface{} // poly.PubPoly
	Signature []byte
}

func (s *SmallSession) SendShareCommitMessages() error {
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
func (s *SmallSession) ReceiveShareCommitMessages() error {

	results := s.ReadAll(func() interface{} {
		commitment := new(poly.PubPoly)
		commitment.Init(s.Suite, s.K, nil)

		message := new(ShareCommitMessage)
		message.Commitment = commitment
		return message
	})

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*ShareCommitMessage)
		if message == nil || !ok {
			return errors.New("ERECV")
		}
		signature := message.Signature
		message.Signature = nil
		data := protobuf.Encode(message)
		err := s.Verify(data, signature, message.Source)
		if err != nil {
			return errors.New("EVERIFY")
		}
		commitment := message.Commitment.(*poly.PubPoly)
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

func (s *SmallSession) SendStatusMessages(status Status) error {
	message := &StatusMessage{ s.Nonce, s.Mine, status, nil }
	signature := s.Sign(protobuf.Encode(message))
	message.Signature = signature
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

func (s *SmallSession) ReceiveStatusMessages() error {
	results := s.ReadAll(func() interface{} {
		return &StatusMessage{ s.Suite.Secret(), 0, FAILURE, nil }
	})

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*StatusMessage)
		if message == nil || !ok {
			return errors.New("ERECV")
		}
		signature := message.Signature
		message.Signature = nil
		data := protobuf.Encode(message)
		err := s.Verify(data, signature, message.Source)
		if err != nil {
			return errors.New("EVERIFY")
		}
		if message.Status != SUCCESS {
			return errors.New("EFAIL")
		}
	}
	return nil
}

type ShareMessage struct {
	Nonce Nonce
	Source int
	Shares []abstract.Secret
	Signature []byte
}

func (s *SmallSession) SendShareMessages() error {
	shares := make([]abstract.Secret, s.N)
	for i, share := range s.shares {
		shares[i] = share.Share(s.Mine)
	}
	message := &ShareMessage{ s.Nonce, s.Mine, shares, nil }
	signature := s.Sign(protobuf.Encode(message))
	message.Signature = signature
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

func (s *SmallSession) ReceiveShareMessages() error {
	results := s.ReadAll(func() interface{} {
		return new(ShareMessage)
	})

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*ShareMessage)
		if message == nil || !ok {
			return errors.New("ERECV")
		}
		signature := message.Signature
		message.Signature = nil
		data := protobuf.Encode(message)
		err := s.Verify(data, signature, message.Source)
		if err != nil {
			return errors.New("EVERIFY")
		}
		source := message.Source
		for i, share := range message.Shares {
			if !s.commitments[i].Check(source, share) {
				return errors.New("ECHECK")
			}
			s.shares[i].SetShare(source, share)
		}
	}
	return nil
}

func (s *SmallSession) CombineShares() (abstract.Secret, error) {
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
