package main

import (
	"errors"
	"fmt"
	"net"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly"
	"rnd/broadcaster"
	"rnd/context"
	"rnd/prefix"
	"time"
)

type LeaderSession struct {
	*SessionBase

	*broadcaster.Broadcaster
}

func NewLeaderSession(context *context.Context, R, Q int) *LeaderSession {

	broadcaster := &broadcaster.Broadcaster {
		make([]net.Conn, context.N),
	}

	session := &LeaderSession {
		NewSessionBase(context, R, Q),
		broadcaster,
	}
	return session
}

func (s *LeaderSession) Start() {
	s.SessionBase.Start()

	// Generate a nonce for the session.
	s.Nonce = s.Suite.Secret()
	s.Nonce.Pick(s.Random)

	// Leader connects to everybody else and announces
	// the sesion using the nonce.
	for i := 0; i < s.N; i++ {
		if s.IsMine(i) {
			continue
		}
		timeout := 3 * time.Second
		conn, err := net.DialTimeout("tcp", s.Peers[i].Addr, timeout)
		if err != nil {
			format := "Unable to connect to server at %s"
			panic(fmt.Sprintf(format, s.Peers[i].Addr))
		}
		buf, _ := s.Nonce.MarshalBinary()
		if _, err := prefix.WritePrefix(conn, buf); err != nil {
			panic("Sending announcement: " + err.Error())
		}
		s.Conns[i] = conn
	}

	// Start running the lottery protocol.
	fmt.Println("Started Leader " + s.Nonce.String())
	s.RunLottery()
}

// Receive an outer commitment from every other client.
func (s *LeaderSession) ReceiveHashCommits() error {
	results := s.ReadAll(func()interface{} {
		return new(HashCommitMessage)
	}, s.cons)

	s.V_C_p = make([][]byte, s.N)
	s.V_C_p[s.Mine] = s.C_i_p

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

// Send the vector of outer commitments to the clients.
func (s *LeaderSession) SendHashCommitVector() error {
	message := &HashCommitVectorMessage { s.V_C_p }
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

// Receive a vector of trustee signatures from all of
// the other clients.
func (s *LeaderSession) ReceiveSignatureVectors() error {
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
			return errors.New("EBAD_ATTESTATION")
		}
		if err := s.validateAttestation(message); err != nil {
			return err
		}
		s.signatureVector[message.Source] = message
	}
	return nil
}

// Send the vector of signature vectors to the clients.
func (s *LeaderSession) SendSignatureVectorVector() error {
	message := &SignatureVectorVectorMessage {
		s.signatureVector,
	}
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

// Receive a secret from all clients. Some adversarial clients
// may not send a valid secret (or a secret at all(, but we'll
// deal with that later.
func (s *LeaderSession) ReceiveSecrets() error {
	results := s.ReadAll(func()interface{} {
		return new(SecretMessage)
	}, s.cons)

	s.secretVector = make([]abstract.Secret, s.N)
	s.secretVector[s.Mine] = s.s_i
	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <- results
		message, ok := msgPtr.(*SecretMessage)
		if !(message == nil || !ok || !s.checkSecret(message.Secret, message.Source)) {
			s.secretVector[message.Source] = message.Secret
		}
	}
	return nil
}

// Request shares of any missing secret from the trustees
// that are holding those shares. For efficiency, we send
// only a single request to each client, batching all shares
// that we need from them.
func (s *LeaderSession) RequestMissingShares() error {
	// Tally up what we need to request and from whom.
	shareKeys := make([][]uint32, s.N)
	for i := range shareKeys {
		shareKeys[i] = make([]uint32, 0, s.N)
	}

	// Keep track of the shares the we receive for
	// interpolation later.
	shares := make([]*poly.PriShares, s.N)

	// Check every secret to see if it's valid.
	// XXX: check for equivocation as well
	for i, signature := range s.signatureVector {
		if s.secretVector[i] == nil {
			fmt.Printf("Missing secret from %d.\n", i)
			shares[i] = new(poly.PriShares)
			shares[i].Empty(s.Suite, s.Q, s.R)

			// Find the trustees holding shares of the missing secret.
			C_i := signature.Commit
			trustees := s.findTrustees(C_i)
			for index, trustee := range trustees {
				key := uint32(i << 16 | index)
				shareKeys[trustee] = append(shareKeys[trustee], key)
			}
		}
	}

	// Send out the batched requests for shares to the clients.
	s.Broadcast(func(i int)interface{} {
		return &ShareRequestMessage{ shareKeys[i] }
	})

	// Receive the requested shares from all clients.
	results := s.ReadAll(func()interface{} {
		return new(ShareMessage)
	}, s.cons)

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <-results
		message, ok := msgPtr.(*ShareMessage)
		if message == nil || !ok {
			continue
		}
		// Fill in the shares that the client sent back.
		for i, key := range shareKeys[message.Source] {
			shares[key >> 16].SetShare(int(key & 0xffff), message.Shares[i])
		}
	}

	// Fill in any shares that we were responsible for as
	// a trustee, if necessary.
	for key, share := range s.shares {
		if shares[key >> 16] != nil {
			shares[key >> 16].SetShare(int(key & 0xffff), share)
		}
	}

	// Use the shares to reconstuct the missing secrets.
	for i := range shares {
		if shares[i] != nil {
			s.secretVector[i] = shares[i].Secret()
		}
	}
	return nil
}

// Send the vector of secrets to the clients.
func (s *LeaderSession) SendSecretVector() error {
	message := &SecretVectorMessage{
		s.secretVector,
	}
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

// The main protocol structure, broken down be step to (hopefully)
// be both easy to follow and easy to evaluate at finer granularity.
func (s *LeaderSession) RunLottery() {
	s.GenerateInitialShares()

	if err := s.ReceiveHashCommits(); err != nil {
		panic("ReceiveHashCommits: " + err.Error())
	}

	if err := s.SendHashCommitVector(); err != nil {
		panic("SendHashCommitVector: " + err.Error())
	}

	go s.HandleSigningRequests()
	s.GenerateTrusteeShares()
	if err := s.SendTrusteeShares(3 * time.Second); err != nil {
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

	if err := s.RequestMissingShares(); err != nil {
		panic("RequestMissingShares: " + err.Error())
	}

	// We may get errors here if adversarial clients go offline
	// entirely, so we just log them and continue on.
	if err := s.SendSecretVector(); err != nil {
		fmt.Println("SendSecretVector: " + err.Error())
	}

	if err := s.CalculateTickets(); err != nil {
		panic("CalculateTickets: " + err.Error())
	}
}
