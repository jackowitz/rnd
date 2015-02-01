package main

import (
	"errors"
	"fmt"
	"net"
	"time"
	"github.com/dedis/crypto/abstract"
	"rnd/broadcaster"
	"rnd/prefix"
)

type LeaderSession struct {
	*SessionBase

	*broadcaster.Broadcaster
}

func NewLeaderSession(context *Context, nonce Nonce) {

	broadcaster := &broadcaster.Broadcaster {
		make([]net.Conn, context.N),
	}

	session := &LeaderSession {
		NewSessionBase(context, nonce),
		broadcaster,
	}

	server, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	incoming := make(chan net.Conn, context.N)
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				continue
			}
			incoming <- conn
		}
	}()

	session.Start(incoming, replyConn, done)
}

var timeout = 3 * time.Second

func (s *LeaderSession) Start(connChan <-chan net.Conn,
		replyConn net.Conn, close chan<- Nonce) {

	// Store connection channel away for later.
	s.ConnChan = connChan

	// Leader connects to everybody else.
	for i := 0; i < s.N; i++ {
		if s.IsMine(i) {
			continue
		}
		conn, err := net.DialTimeout("tcp", s.Peers[i].Addr, timeout)
		if err != nil {
			format := "Unable to connect to server at %s"
			panic(fmt.Sprintf(format, s.Peers[i].Addr))
		}
		buf := s.Nonce.Encode()
		if _, err := prefix.WritePrefix(conn, buf); err != nil {
			panic("announcement: " + err.Error())
		}
		s.Conns[i] = conn
	}
	fmt.Println("Started Leader " + s.Nonce.String())
	s.RunLottery()
}

func (s *LeaderSession) GenerateInitialShares() {
	s.s_i.Pick(s.Random)
	s.C_i.Mul(nil, s.s_i)

	h := s.Suite.Hash()
	h.Write(s.C_i.Encode())
	s.C_i_p = h.Sum(nil)
}

func (s *LeaderSession) ReceiveHashCommits() error {
	results := s.ReadAll(func()interface{} {
		return new(HashCommitMessage)
	}, s.cons)

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*HashCommitMessage)
		if message == nil || !ok {
			return errors.New("EBAD_COMMIT")
		}
		s.V_C_p[message.Source] = message.Commit
	}
	return nil
}

type HashCommitVectorMessage struct {
	Commits [][]byte
}

func (s *LeaderSession) SendHashCommitVector() error {
	message := &HashCommitVectorMessage { s.V_C_p }
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

func (s *LeaderSession) ReceiveSignatureVectors() error {
	fmt.Println("Waiting for signature vectors...")
	results := s.ReadAll(func()interface{} {
		return new(SignatureVectorMessage)
	}, s.cons)

	s.signatureVector = make([]*SignatureVectorMessage, s.N)
	s.signatureVector[s.Mine] = &SignatureVectorMessage{
		s.Mine, s.C_i, s.signatures,
	}
	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*SignatureVectorMessage)
		if message == nil || !ok {
			return errors.New("EBAD_COMMIT")
		}
		s.signatureVector[message.Source] = message
	}
	fmt.Println("Got all signature vectors.")
	return nil
}

type SignatureVectorVectorMessage struct {
	Signatures []*SignatureVectorMessage
}

func (s *LeaderSession) SendSignatureVectorVector() error {
	message := &SignatureVectorVectorMessage {
		s.signatureVector,
	}
	fmt.Println("Sent signature vector vector.")
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

func (s *LeaderSession) ReceiveSecrets() error {
	results := s.ReadAll(func()interface{} {
		return new(SecretMessage)
	}, s.cons)

	s.secretVector = make([]abstract.Secret, s.N)
	s.secretVector[s.Mine] = s.s_i
	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*SecretMessage)
		if message == nil || !ok {
			return errors.New("EBAD_COMMIT")
		}
		s.secretVector[message.Source] = message.Secret
	}
	fmt.Println("Got all secrets.")
	return nil
}

type SecretVectorMessage struct {
	Secrets []abstract.Secret
}

func (s *LeaderSession) SendSecretVector() error {
	message := &SecretVectorMessage{
		s.secretVector,
	}
	fmt.Println("Sent secret vector.")
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

func (s *LeaderSession) RunLottery() {
	s.GenerateInitialShares()
	s.V_C_p[s.Mine] = s.C_i_p

	if err := s.ReceiveHashCommits(); err != nil {
		panic("ReceiveHashCommits: " + err.Error())
	}

	if err := s.SendHashCommitVector(); err != nil {
		panic("SendHashCommitVector: " + err.Error())
	}

	go s.HandleSigningRequests()
	s.GenerateTrusteeShares(s.K, s.N)
	if err := s.SendTrusteeShares(s.N); err != nil {
		panic("SendTrusteeShares: " + err.Error())
	}

	if err := s.ReceiveSignatureVectors(); err != nil {
		panic("ReceiveSignatureVectors: " + err.Error())
	}

	if err := s.SendSignatureVectorVector(); err != nil {
		panic("SendSignatureVectorVector: " + err.Error())
	}

	if err := s.ReceiveSecrets(); err != nil {
		panic("ReceiveSecrets: " + err.Error())
	}

	if err := s.SendSecretVector(); err != nil {
		panic("SendSecretVector: " + err.Error())
	}

	if err := s.CalculateTickets(); err != nil {
		panic("CalculateTickets: " + err.Error())
	}
}
