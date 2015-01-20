package main

import (
	"fmt"
	"net"
	"github.com/dedis/crypto/abstract"
)

type ScalableSession struct {
	*Context
	Nonce Nonce

	Conn net.Conn

	// Protocol-specific fields
	s_i abstract.Secret
	C_i abstract.Point
	C_i_p []byte
}

func (s *ScalableSession) Start(connChan <-chan Connection,
		replyConn net.Conn, close chan<- Nonce) {

	conn := <- connChan
	s.Conn = conn.Conn

	fmt.Println("Started " + s.Nonce.String())
	s.RunLottery()
}

func (s *ScalableSession) GenerateInitialShares() {
	s.s_i.Pick(s.Random)
	s.C_i.Mul(nil, s.s_i)

	h := s.Suite.Hash()
	h.Write(s.C_i.Encode())
	s.C_i_p = h.Sum(nil)
}

func (s *ScalableSession) RunLottery() {
	s.GenerateInitialShares()
}
