package main

import (
	"errors"
	"fmt"
	"net"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/poly"
	"rnd/broadcaster"
	"rnd/context"
	"rnd/prefix"
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

var timeout = 3 * time.Second

func (s *LeaderSession) Start() {
	// Start up any core session stuff, namely a listen
	// socket for trustee requests later.
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
	fmt.Println("Got all HashCommits.")
	return nil
}

func (s *LeaderSession) SendHashCommitVector() error {
	message := &HashCommitVectorMessage { s.V_C_p }
	fmt.Println("Sent HashCommitVector.")
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

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
			return errors.New("EBAD_COMMIT")
		}
		s.signatureVector[message.Source] = message
	}
	fmt.Println("Got all SignatureVectors.")
	return nil
}

func (s *LeaderSession) SendSignatureVectorVector() error {
	message := &SignatureVectorVectorMessage {
		s.signatureVector,
	}
	fmt.Println("Sent SignatureVectorVector.")
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
		if ok && message != nil {
			s.secretVector[message.Source] = message.Secret
		}
	}
	fmt.Println("Got all Secrets.")
	return nil
}

func (s *LeaderSession) RequestMissingShares() error {
	// Tally up what we need to request and from whom.
	shareKeys := make([][]uint32, s.N)
	for i := range shareKeys {
		shareKeys[i] = make([]uint32, 0, s.N)
	}

	// Might as well prep the shares now while we're at it.
	shares := make([]*poly.PriShares, s.N)

	for i, signature := range s.signatureVector {
		if s.secretVector[i] == nil {
			fmt.Printf("Missing secret from %d.\n", i)
			shares[i] = new(poly.PriShares)
			shares[i].Empty(s.Suite, s.K, s.N)

			C_i := signature.Commit
			trustees := s.findTrustees(C_i)
			for index, trustee := range trustees {
				key := uint32(i << 16 | index)
				fmt.Printf("Requesting %d, %d from %d.\n", i, index, trustee)
				shareKeys[trustee] = append(shareKeys[trustee], key)
			}
		}
	}

	// Send out the requests for shares.
	err := s.Broadcast(func(i int)interface{} {
		return &ShareRequestMessage{ shareKeys[i] }
	})
	if err != nil {
		return err
	}

	// Wait to hear back from everyone.
	results := s.ReadAll(func()interface{} {
		return new(ShareMessage)
	}, s.cons)

	for pending := s.N-1; pending > 0; pending-- {
		msgPtr := <-results
		message, ok := msgPtr.(*ShareMessage)
		if message == nil || !ok {
			continue
		}
		for i, key := range shareKeys[message.Source] {
			fmt.Printf("Got %d, %d from %d.\n", key>>16, key&0xffff, message.Source)
			shares[key >> 16].SetShare(int(key & 0xffff), message.Shares[i])
		}
		// Fill in any shares we've been holding, if needed.
		for key, share := range s.shares {
			if shares[key >> 16] != nil {
				shares[key >> 16].SetShare(int(key & 0xffff), share)
			}
		}
	}

	for i := range shares {
		if shares[i] != nil {
			s.secretVector[i] = shares[i].Secret()
		}
	}
	return nil
}

func (s *LeaderSession) SendSecretVector() error {
	message := &SecretVectorMessage{
		s.secretVector,
	}
	fmt.Println("Sent SecretVector.")
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
	s.GenerateTrusteeShares()
	if err := s.SendTrusteeShares(); err != nil {
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

	if err := s.SendSecretVector(); err != nil {
		//panic("SendSecretVector: " + err.Error())
		fmt.Println("SendSecretVector: " + err.Error())
	}

	if err := s.CalculateTickets(); err != nil {
		panic("CalculateTickets: " + err.Error())
	}
}
