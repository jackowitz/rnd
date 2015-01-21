package main

import (
	"net"
	"github.com/dedis/crypto/protobuf"
)

type Server struct {
	*Context
	Protocol

	// Session management stuff.
	sessions map[string] chan <-net.Conn
	done chan Nonce
}

func (s *Server) AcceptsRequests() bool {
	return s.Mine == 0
}

func NewServer(context *Context, protocol Protocol) *Server {

	sessions := make(map[string]chan <-net.Conn)
	done := make(chan Nonce)

	return &Server{
		context,
		protocol,
		sessions,
		done,
	}
}

// Need to wrap Nonce to play nice with protobuf.
type NonceMessage struct {
	Nonce Nonce
}

func (s *Server) HandleConnection(conn net.Conn) error {
	// Extract the Nonce.
	buf, err := ReadPrefix(conn);
	if err != nil {
		return err
	}
	message := &NonceMessage{ s.Suite.Secret() }
	if err := protobuf.Decode(buf, message, nil); err != nil {
		return err
	}
	nonce := message.Nonce

	// See if there's already a session for that Nonce and,
	// if not, start up a new one.
	forward, ok := s.sessions[nonce.String()]
	if !ok {
		forward = s.NewSession(s.Context, nonce, nil, s.done)
		s.sessions[nonce.String()] = forward
	}

	// Finally, forward the connection to the proper Session.
	forward <- conn
	return nil
}

func (s *Server) Start() {
	// Start listening for connections from peers.
	incoming, err := Listen(s.Self().Addr)
	if err != nil {
		panic("ListenPeers: " + err.Error())
	}

	// Leader listens for requests to generate values.
	var requests <-chan net.Conn
	if s.AcceptsRequests() {
		requests, err = Listen(":7999")
		if err != nil {
			panic("ListenRequests: " + err.Error())
		}
	}

	for {
		select {
		case conn := <-incoming:
			if err := s.HandleConnection(conn); err != nil {
				panic("HandleConnection: " + err.Error())
			}
		case conn := <-requests:
			nonce := s.NextNonce()
			forward := s.NewLeaderSession(s.Context, nonce, conn, s.done)
			s.sessions[nonce.String()] = forward
		case nonce := <-s.done:
			forward, ok := s.sessions[nonce.String()]
			if ok {
				close(forward)
				delete(s.sessions, nonce.String())
			}
		}
	}
}

// Spawns a new goroutine and returns immediately with a channel
// on which that goroutine delivers accepted connections.
func Listen(addr string) (<-chan net.Conn, error) {
	server, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	incoming := make(chan net.Conn)
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				continue
			}
			incoming <- conn
		}
	}()
	return incoming, nil
}
