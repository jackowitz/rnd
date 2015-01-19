package main

import (
	"errors"
	"net"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/protobuf"
)

type Session struct {
	*Context
	Nonce Nonce

	Conns []net.Conn

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
		done chan<- Nonce) chan <-Connection {

	conns := make([]net.Conn, context.N)

	session := &Session{ context, nonce, conns,
		context.Suite.Secret(), new(poly.PriPoly), new(poly.PriShares),
		new(poly.PubPoly), make([]*poly.PriShares, context.N),
		make([]*poly.PubPoly, context.N)}

	for i := range session.shares {
		session.shares[i] = new(poly.PriShares)
		session.shares[i].Empty(session.Suite, session.K, session.N)
	}

	incoming := make(chan Connection)
	go session.Start(incoming, replyConn, done)

	return incoming
}

func (s *Session) IsMine(i int) bool {
	return i == s.Mine
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

// Higher order function to handle broadcasting a type of message
// to all peers. Take a contructor to make the messages based on
// the id of the peer.
func (s *Session) Broadcast(constructor func(int)interface{}) error {

	for i, conn := range s.Conns {
		if s.IsMine(i) {
			continue
		}
		data := constructor(i)
		message := &Message{ s.Mine, protobuf.Encode(data), nil }
		s.Sign(message)
		raw := protobuf.Encode(message)
		if _, err := WritePrefix(conn, raw); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) ReadOne(conn net.Conn, constructor func()interface{},
		verify bool, results chan<- interface{}) {

	// XXX should probably pull this out
	cons := protobuf.Constructors{
		tSecret: func()interface{} { return s.Suite.Secret() },
		tNonce: func()interface{} { return s.Suite.Secret() },
	}

	timeout := 2 * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	raw, err := ReadPrefix(conn)
	if err != nil {
		results <- nil
	}
	wrapper := new(Message)
	err = protobuf.Decode(raw, wrapper, nil)
	if err != nil {
		results <- nil
	}
	if err := s.Verify(wrapper); err != nil {
		results <- nil
	}
	data := wrapper.Data
	message := constructor()
	err = protobuf.Decode(data, message, cons)
	if err != nil {
		results <- nil
	}
	results <- message
}

// Higher order function for reading the same type of message from all
// of our peers. Spawns a goroutine for each peer and delivers
// the results on the returned channel.
func (s *Session) ReadAll(cons func()interface{},
		verify bool) <-chan interface{} {

	results := make(chan interface{}, s.N)
	for i, conn := range s.Conns {
		if s.IsMine(i) { continue }
		go s.ReadOne(conn, cons, verify, results)
	}
	return results
}

type ShareCommitMessage struct {
	Nonce Nonce

	Index, Source int
	Share abstract.Secret
	Commitment interface{} // poly.PubPoly
}

func (s *Session) SendShareCommitMessages() error {
	return s.Broadcast(func (i int) interface{} {
		return &ShareCommitMessage{ s.Nonce, i, s.Mine,
				s.s_i.Share(i), s.p_i }
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

func (s *Session) SendStatusMessages(status Status) error {
	message := &StatusMessage{ s.Nonce, s.Mine, status }
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

func (s *Session) ReceiveStatusMessages() error {
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

func (s *Session) SendShareMessages() error {
	shares := make([]abstract.Secret, s.N)
	for i, share := range s.shares {
		shares[i] = share.Share(s.Mine)
	}
	message := &ShareMessage{ s.Nonce, s.Mine, shares }
	return s.Broadcast(func (i int) interface{} {
		return message
	})
}

func (s *Session) ReceiveShareMessages() error {
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
