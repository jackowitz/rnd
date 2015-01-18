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
func NewSession(context *Context, nonce Nonce, requester net.Conn,
		done chan<- Nonce) chan <-Connection {

	conns := make([]net.Conn, context.N)

	session := &Session{ context, nonce, conns, context.Suite.Secret(),
		new(poly.PriPoly), new(poly.PriShares), new(poly.PubPoly),
		make([]*poly.PriShares, context.N), make([]*poly.PubPoly, context.N)}

	for i := range session.shares {
		session.shares[i] = new(poly.PriShares)
		session.shares[i].Empty(session.Suite, session.K, session.N)
	}

	incoming := make(chan Connection)
	go session.Start(incoming, requester, done)

	return incoming
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

func (s *Session) IsMine(i int) bool {
	return i == s.Mine
}

func (s *Session) NewShareCommitMessage(i int) *ShareCommitMessage {
	return &ShareCommitMessage{ s.Nonce, i, s.Mine, s.s_i.Share(i), s.p_i }
}

// Sends out all of the ShareCommitMessages. If we get an error on
// any of them we break, as that's bad.
func (s *Session) SendShareCommitMessages() error {
	for i, conn := range s.Conns {
		if s.IsMine(i) {
			continue
		}
		share := s.NewShareCommitMessage(i)
		message := s.Sign(share)
		if err := send(conn, &message); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) EmptyShareCommitMessage() *ShareCommitMessage {
	commitment := new(poly.PubPoly)
	commitment.Init(s.Suite, s.K, nil)
	return &ShareCommitMessage{ s.Suite.Secret(), 0, 0,
			s.Suite.Secret(), commitment }
}

func (s *Session) ReadOne(conn net.Conn, constructor func()interface{},
		results chan<- interface{}) {

	cons := protobuf.Constructors{
		tSecret: func()interface{} { return s.Suite.Secret() },
		tNonce: func()interface{} { return s.Suite.Secret() },
	}

	conn.SetReadDeadline(time.Now().Add(2*time.Second))

	wrapper := Message{}
	if err := receive(conn, &wrapper); err != nil {
		results <- nil
	}
	message := constructor()
	if err := protobuf.Decode(wrapper.Data, message, cons); err != nil {
		results <- nil
	}
	// XXX verify commitment
	results <- message
}

// Helper function for reading the same type of message from all
// of our peers. Spawns a goroutine for each peer and delivers
// the results on the returned channel.
func (s *Session) ReadAll(cons func()interface{}) <-chan interface{} {
	results := make(chan interface{}, s.N)
	for i, conn := range s.Conns {
		if s.IsMine(i) { continue }
		go s.ReadOne(conn, cons, results)
	}
	return results
}

// Tries to receive a ShareCommitMessage from all N peers. If we
// get fewer than N, we error out, since we want the initial shares
// from everybody, not just threshold K.
func (s *Session) ReceiveShareCommitMessages() error {

	results := s.ReadAll(func() interface{} {
		return s.EmptyShareCommitMessage()
	})

	for pending := s.N-1; pending > 0; pending-- {
		message := <- results
		sc, ok := message.(*ShareCommitMessage)
		if sc == nil || !ok {
			return errors.New("ERECV")
		}
		source := sc.Source
		s.shares[source].SetShare(sc.Index, sc.Share)
		s.commitments[source] = sc.Commitment.(*poly.PubPoly)
	}
	return nil
}

func (s *Session) SendStatusMessages(status Status) error {
	data := StatusMessage{ s.Nonce, s.Mine, status }
	message := s.Sign(&data)
	for i, conn := range s.Conns {
		if s.IsMine(i) {
			continue
		}
		if err := send(conn, &message); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) ReceiveStatusMessages() error {
	results := s.ReadAll(func() interface{} {
		return &StatusMessage{ s.Suite.Secret(), 0, FAILURE }
	})

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

func (s *Session) NewShareMessage() *ShareMessage {
	shares := make([]abstract.Secret, s.N)
	for i, share := range s.shares {
		shares[i] = share.Share(s.Mine)
	}
	return &ShareMessage{ s.Nonce, s.Mine, shares }
}

func (s *Session) SendShareMessages() error {
	data := s.NewShareMessage()
	message := s.Sign(data)
	for i, conn := range s.Conns {
		if s.IsMine(i) {
			continue
		}
		if err := send(conn, &message); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) ReceiveShareMessages() error {
	results := s.ReadAll(func() interface{} {
		return &ShareMessage{}
	})

	for pending := s.N-1; pending > 0; pending-- {
		message := <- results
		shares, ok := message.(*ShareMessage)
		if shares == nil || !ok {
			return errors.New("ERECV")
		}
		source := shares.Source
		for i, share := range shares.Shares {
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
