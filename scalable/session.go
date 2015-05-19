package main

import (
	"errors"
	"fmt"
	"net"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/protobuf"
	"rnd/broadcaster"
	"rnd/context"
	"rnd/prefix"
	"time"
)

// Functionality specific to sessions run on all servers
// other than the leader.
type Session struct {
	*SessionBase
	isAdversary bool

	Conn net.Conn
}

func NewSession(context *context.Context, R, Q int, isAdversary bool) *Session {
	session := &Session {
		NewSessionBase(context, R, Q),
		isAdversary,
		nil,
	}
	return session
}

func (s *Session) Start() {
	// Start up any core session stuff, namely a listen
	// socket for trustee requests later.
	s.SessionBase.Start()

	// Get our connection to the leader.
	s.Conn = <- s.ConnChan
	buf, err := prefix.ReadPrefix(s.Conn)
	if err != nil {
		panic("Reading Nonce: " + err.Error())
	}
	s.Nonce = s.Suite.Secret()
	if err = s.Nonce.UnmarshalBinary(buf); err != nil {
		panic("Decoding Nonce: " + err.Error())
	}

	// Start running the lottery protocol.
	fmt.Println("Started " + s.Nonce.String())
	s.RunLottery()
}

// Send the outer commitment to the leader.
func (s *Session) SendHashCommit() error {
	message, _ := protobuf.Encode(&HashCommitMessage{ s.Mine, s.C_i_p })
	_, err := prefix.WritePrefix(s.Conn, message)
	fmt.Println("Sent HashCommit.")
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

var EADVERSARY = errors.New("Adversarial failure")

// Send our secret to the leader.
func (s *Session) SendSecret() error {
	if s.isAdversary {
		return EADVERSARY
	}
	message, _ := protobuf.Encode(&SecretMessage{
		s.Mine, s.s_i,
	})
	_, err := prefix.WritePrefix(s.Conn, message)
	fmt.Println("Sent Secret.")
	return err
}

// Somebody didn't send their secret, we need to help reconstruct
// it using the shares that we're holding.
func (s *Session) ReceiveShareRequests() error {
	fmt.Println("Got ShareRequest.")
	message := new(ShareRequestMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	shares := make([]abstract.Secret, len(message.Keys))
	for i, key := range message.Keys {
		shares[i] = s.shares[key]
		fmt.Printf("Sending %d, %d (%s)to leader.\n", key>>16,
			key&0xffff, shares[i])
	}

	reply, _ := protobuf.Encode(&ShareMessage{
		s.Mine, shares,
	})
	_, err := prefix.WritePrefix(s.Conn, reply)
	fmt.Println("Sent Shares.")
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

func (s *Session) RunLottery() {

	s.GenerateInitialShares()
	if err := s.SendHashCommit(); err != nil {
		panic("SendHashCommit: " + err.Error())
	}

	if err := s.ReceiveHashCommitVector(); err != nil {
		panic("ReceiveHashCommitVector: " + err.Error())
	}

	go s.HandleSigningRequests()
	s.GenerateTrusteeShares()
	if err := s.SendTrusteeShares(3 * time.Second); err != nil {
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

	if err := s.ReceiveShareRequests(); err != nil {
		panic("ReceiveShareRequests: " + err.Error())
	}

	if err := s.ReceiveSecretVector(); err != nil {
		panic("ReceiveSecretVector: " + err.Error())
	}

	if err := s.CalculateTickets(); err != nil {
		panic("CalculateTickets: " + err.Error())
	}
}
