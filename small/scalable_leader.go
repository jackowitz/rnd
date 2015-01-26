package main

import (
	"errors"
	"fmt"
	"net"
	//"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/protobuf"
)

type ScalableLeaderSession struct {
	*ScalableSessionBase

	*Broadcaster
}

func NewScalableLeaderSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-net.Conn {

	broadcaster := &Broadcaster {
		make([]net.Conn, context.N),
	}

	scalable := &ScalableLeaderSession {
		NewScalableSessionBase(context, nonce),
		broadcaster,
	}

	incoming := make(chan net.Conn, context.N)
	go scalable.Start(incoming, replyConn, done)

	return incoming
}

func (s *ScalableLeaderSession) Start(connChan <-chan net.Conn,
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
		buf := protobuf.Encode(&NonceMessage{ s.Nonce })
		if _, err := WritePrefix(conn, buf); err != nil {
			panic("announcement: " + err.Error())
		}
		s.Conns[i] = conn
	}
	fmt.Println("Started Leader " + s.Nonce.String())
	s.RunLottery()
}

func (s *ScalableLeaderSession) GenerateInitialShares() {
	s.s_i.Pick(s.Random)
	s.C_i.Mul(nil, s.s_i)

	h := s.Suite.Hash()
	h.Write(s.C_i.Encode())
	s.C_i_p = h.Sum(nil)
}

func (s *ScalableLeaderSession) ReceiveHashCommits() error {
	results := s.ReadAll(func()interface{} {
		return new(HashCommitMessage)
	}, nil)

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

func (s *ScalableLeaderSession) SendHashCommitVector() error {
	message := &HashCommitVectorMessage { s.V_C_p }
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

func (s *ScalableLeaderSession) ReceiveSignatureVectors() error {
	fmt.Println("Waiting for signature vectors...")
	results := s.ReadAll(func()interface{} {
		return new(SignatureVectorMessage)
	}, nil)

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

func (s *ScalableLeaderSession) SendSignatureVectorVector() error {
	message := &SignatureVectorVectorMessage {
		s.signatureVector,
	}
	return s.Broadcast(func(i int)interface{} {
		return message
	})
}

func (s *ScalableLeaderSession) RunLottery() {
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
}
