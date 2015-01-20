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
		done chan<- Nonce) chan <-Connection {

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

	incoming := make(chan Connection)
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

func (s *SmallSession) Start(connChan <-chan Connection,
		replyConn net.Conn, close chan<- Nonce) {

	for i := s.Mine + 1; i < s.N; i++ {
		conn, err := net.DialTimeout("tcp", s.Peers[i].Addr, timeout)
		if err != nil {
			format := "Unable to connect to server at %s"
			panic(fmt.Sprintf(format, s.Peers[i].Addr))
		}
		data := &AnnouncementMessage{ s.Nonce, s.Mine }
		message := &Message{ s.Mine, protobuf.Encode(data), nil }
		s.Sign(message)
		raw := protobuf.Encode(message)
		if _, err := WritePrefix(conn, raw); err != nil {
			panic("announcement: " + err.Error())
		}
		s.Conns[i] = conn
	}

	// wait for connection from all servers with id less than ours
	for i := 0; i < s.Mine; i++ {
		connection := <- connChan
		s.Conns[connection.Message.Id] = connection.Conn
	}

	// no more connections for this session, notify
	// the main loop to clean up the map
	close <- s.Nonce

	// everyone's all wired up, so start the protocol
	value, stopwatch := s.GenerateRandom()
	if debug {
		format := "[%d, %d] Times: %s\n"
		fmt.Printf(format, s.N, s.K, stopwatch)
		fmt.Printf("Value: %s\n", value.String())
	}
	if replyConn != nil {
		if _, err := replyConn.Write(value.Encode()); err != nil {
			panic("reply send: " + err.Error())
		}
	}

	if replyConn != nil {
		if err := replyConn.Close(); err != nil {
			panic("reply close: " + err.Error())
		}
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

type Message struct {
	Source int
	Data []byte
	Signature []byte
}

type ShareCommitMessage struct {
	Nonce Nonce

	Index, Source int
	Share abstract.Secret
	Commitment interface{} // poly.PubPoly
}

func (s *SmallSession) SendShareCommitMessages() error {
	return s.Broadcast(func (i int) interface{} {
		return &ShareCommitMessage{ s.Nonce, i, s.Mine,
				s.s_i.Share(i), s.p_i }
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
	}, true)

	for pending := s.N-1; pending > 0; pending-- {
		message := <- results
		sc, ok := message.(*ShareCommitMessage)
		if sc == nil || !ok {
			return errors.New("ERECV")
		}
		commitment := sc.Commitment.(*poly.PubPoly)
		if !commitment.Check(sc.Index, sc.Share) {
			return errors.New("ECHECK")
		}
		source := sc.Source
		s.shares[source].SetShare(sc.Index, sc.Share)
		s.commitments[source] = sc.Commitment.(*poly.PubPoly)
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
}

func (s *SmallSession) SendStatusMessages(status Status) error {
	message := &StatusMessage{ s.Nonce, s.Mine, status }
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

func (s *SmallSession) ReceiveStatusMessages() error {
	results := s.ReadAll(func() interface{} {
		return &StatusMessage{ s.Suite.Secret(), 0, FAILURE }
	}, true)

	for pending := s.N-1; pending > 0; pending-- {
		message := <- results
		status, ok := message.(*StatusMessage)
		if status == nil || !ok {
			return errors.New("ERECV")
		}
		if status.Status != SUCCESS {
			return errors.New("EFAIL")
		}
	}
	return nil
}

type ShareMessage struct {
	Nonce Nonce

	Source int
	Shares []abstract.Secret
}

func (s *SmallSession) SendShareMessages() error {
	shares := make([]abstract.Secret, s.N)
	for i, share := range s.shares {
		shares[i] = share.Share(s.Mine)
	}
	message := &ShareMessage{ s.Nonce, s.Mine, shares }
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

func (s *SmallSession) ReceiveShareMessages() error {
	results := s.ReadAll(func() interface{} {
		return new(ShareMessage)
	}, true)

	for pending := s.N-1; pending > 0; pending-- {
		message := <- results
		shares, ok := message.(*ShareMessage)
		if shares == nil || !ok {
			return errors.New("ERECV")
		}
		source := shares.Source
		for i, share := range shares.Shares {
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
