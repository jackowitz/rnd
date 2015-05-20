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

// Functionality specific to clients other than the leader.
type Session struct {
	*SessionBase

	isAdversary bool	// Adversary won't reveal secret.
	Conn net.Conn		// Connection to the leader.
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
	s.SessionBase.Start()

	// Get a connection to the leader. For now we assume
	// it's the first connection we get, although this could
	// definitely be more robust.
	s.Conn = <- s.ConnChan

	// Get the nonce used to identify the session.
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
	return err
}

// Receive the vector of outer commitments from the leader.
func (s *Session) ReceiveHashCommitVector() error {
	message := new(HashCommitVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, nil); err != nil {
		return err
	}
	s.V_C_p = message.Commits
	return nil
}

// Send our vector of signatures to the leader.
func (s *Session) SendSignatureVector() error {
	message,_ := protobuf.Encode(&SignatureVectorMessage{
		s.Mine, s.C_i, s.signatures,
	})
	_, err := prefix.WritePrefix(s.Conn, message)
	return err
}

// Receive the vector of signature vectors from the leader.
func (s *Session) ReceiveSignatureVectorVector() error {
	message := new(SignatureVectorVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	// Independently validate that all client's signature vectors
	// check out.
	for _, attestation := range message.Signatures {
		if err := s.validateAttestation(attestation); err != nil {
			return err
		}
	}
	s.signatureVector = message.Signatures
	return nil
}

// Error used to indicated that the failure was expected.
// Purely for experimentation purposes.
var EADVERSARY = errors.New("Adversarial failure")

// Send our secret to the leader, unless we're an adversary,
// in which case we just stop and laugh maniacally
func (s *Session) SendSecret() error {
	if s.isAdversary {
		return EADVERSARY
	}
	message, _ := protobuf.Encode(&SecretMessage{
		s.Mine, s.s_i,
	})
	_, err := prefix.WritePrefix(s.Conn, message)
	return err
}

// Somebody didn't send their secret, we need to help reconstruct
// it using the shares that we're holding.
// For now, we always perform such requests, even if there are
// no missing shares, in which case both the request and response
// message will be empty. This can definitely be optimized away.
func (s *Session) HandleSharesRequest() error {
	// Read the share request from the leader.
	message := new(ShareRequestMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	// Lookup the shares that are being requested. If for some
	// reason we don't have a share, send back a nil and let the
	// leader resolve it when trying to reconstuct the secret.
	// The order of shares in the reply matches the order of the
	// keys in the request.
	shares := make([]abstract.Secret, len(message.Keys))
	for i, key := range message.Keys {
		shares[i] = s.shares[key]
	}

	// Send the shares back to the leader in a single message.
	reply, _ := protobuf.Encode(&ShareMessage{
		s.Mine, shares,
	})
	_, err := prefix.WritePrefix(s.Conn, reply)
	return err
}

// Receive the vector of secrets from the leader.
func (s *Session) ReceiveSecretVector() error {
	message := new(SecretVectorMessage)
	if err := broadcaster.ReadOne(s.Conn, message, s.cons); err != nil {
		return err
	}
	for i, secret := range message.Secrets {
		if !s.checkSecret(secret, i) {
			return errors.New("Somehow still got a bad secret?!")
		}
	}
	s.secretVector = message.Secrets
	return nil
}

// The main protocol structure, broken down be step to (hopefully)
// be both easy to follow and easy to evaluate at finer granularity.
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

	if err := s.HandleSharesRequest(); err != nil {
		panic("ReceiveShareRequests: " + err.Error())
	}

	if err := s.ReceiveSecretVector(); err != nil {
		panic("ReceiveSecretVector: " + err.Error())
	}

	if err := s.CalculateTickets(); err != nil {
		panic("CalculateTickets: " + err.Error())
	}
}
