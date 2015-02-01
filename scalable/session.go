package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/protobuf"
	"rnd/broadcaster"
	"rnd/prefix"
)

// Specific to just the others.
type Session struct {
	*SessionBase

	Conn net.Conn
}

func NewSession(context *Context, nonce Nonce) {

	scalable := &Session {
		NewSessionBase(context, nonce),
		nil,
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

	scalable.Start(incoming, replyConn, done)
}

func (s *Session) Start(connChan <-chan net.Conn,
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

func (s *Session) SendHashCommit() error {
	message := protobuf.Encode(&HashCommitMessage{ s.Mine, s.C_i_p })
	_, err := prefix.WritePrefix(s.Conn, message)
	return err
}

func (s *Session) ReceiveHashCommitVector() error {
	message := new(HashCommitVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, nil); err != nil {
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

func (s *Session) SendSignatureVector() error {
	message := protobuf.Encode(&SignatureVectorMessage{
		s.Mine, s.C_i, s.signatures,
	})
	_, err := prefix.WritePrefix(s.Conn, message)
	fmt.Println("Sent SignatureVector.")
	return err
}

func (s *Session) ReceiveSignatureVectorVector() error {
	message := new(SignatureVectorVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
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

func (s *Session) SendSecret() error {
	message := protobuf.Encode(&SecretMessage{
		s.Mine, s.s_i,
	})
	_, err := prefix.WritePrefix(s.Conn, message)
	fmt.Println("Sent Secret.")
	return err
}

func (s *Session) ReceiveSecretVector() error {
	message := new(SecretVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	s.secretVector = message.Secrets
	fmt.Println("Got secret vector.")
	return nil
}

func (s *SessionBase) CalculateTickets() error {
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

func (s *Session) RunLottery() {

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
