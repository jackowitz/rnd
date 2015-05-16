package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/protobuf"
	"rnd/broadcaster"
	"rnd/prefix"
)

// Functionality specific to sessions run on all servers
// other than the leader.
type Session struct {
	*SessionBase

	Conn net.Conn
}

func NewSession(context *Context) {

	scalable := &Session {
		NewSessionBase(context),
		nil,
	}

	server, err := net.Listen("tcp", context.Self().Addr)
	if err != nil {
		panic("Listen: " + err.Error())
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
	scalable.Start(incoming)
}

func (s *Session) Start(connChan <-chan net.Conn) {

	// Get our connection to the leader.
	s.Conn = <- connChan
	buf, err := prefix.ReadPrefix(s.Conn)
	if err != nil {
		panic("Reading Nonce: " + err.Error())
	}
	s.Nonce = s.Suite.Secret()
	if err = s.Nonce.UnmarshalBinary(buf); err != nil {
		panic("Decoding Nonce: " + err.Error())
	}

	// Keep a reference to the channel for accepting
	// requests later as a trustee.
	s.ConnChan = connChan

	// Start running the lottery protocol.
	fmt.Println("Started " + s.Nonce.String())
	s.RunLottery()
}

// The outer commitment to the secret.
type HashCommitMessage struct {
	Source int
	Commit []byte
}

// Send the outer commitment to the leader.
func (s *Session) SendHashCommit() error {
	message, _ := protobuf.Encode(&HashCommitMessage{ s.Mine, s.C_i_p })
	_, err := prefix.WritePrefix(s.Conn, message)
	fmt.Println("Sent hash commit.")
	return err
}

// Receive the vector of outer commitments from the leader.
func (s *Session) ReceiveHashCommitVector() error {
	message := new(HashCommitVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, nil); err != nil {
		return err
	}
	s.V_C_p = message.Commits
	fmt.Println("Got HashCommitVector.")
	return nil
}

// The vector of signatures from trustees.
type SignatureVectorMessage struct {
	Source int
	Commit abstract.Point
	Signatures []*TrusteeSignatureMessage
}

// Send our vector of signatures to the leader.
func (s *Session) SendSignatureVector() error {
	message,_ := protobuf.Encode(&SignatureVectorMessage{
		s.Mine, s.C_i, s.signatures,
	})
	_, err := prefix.WritePrefix(s.Conn, message)
	fmt.Println("Sent SignatureVector.")
	return err
}

// Receive the vector of signature vectors from the leader.
func (s *Session) ReceiveSignatureVectorVector() error {
	message := new(SignatureVectorVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	s.signatureVector = message.Signatures
	fmt.Println("Got SignatureVectorVector.")
	return nil
}

// The opened inner commitment - i.e. the secret.
type SecretMessage struct {
	Source int
	Secret abstract.Secret
}

// Send our secret to the leader.
func (s *Session) SendSecret() error {
	message, _ := protobuf.Encode(&SecretMessage{
		s.Mine, s.s_i,
	})
	_, err := prefix.WritePrefix(s.Conn, message)
	fmt.Println("Sent Secret.")
	return err
}

// Receive the vector of secrets from the leader.
func (s *Session) ReceiveSecretVector() error {
	message := new(SecretVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	s.secretVector = message.Secrets
	fmt.Println("Got SecretVector.")
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
