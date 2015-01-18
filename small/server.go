package main

import (
	"net"
	"github.com/dedis/crypto/protobuf"
)

type Server struct {
	*Context

	// Session management stuff.
	Sessions map[string] chan <-Connection
	Done chan Nonce
}

func (s *Server) AcceptsRequests() bool {
	return s.Mine == 0
}

func NewServer(c *Context) *Server {
	sessions := make(map[string]chan <-Connection)
	done := make(chan Nonce)

	return &Server{ c, sessions, done }
}

func (s *Server) HandleConnection(conn net.Conn) error {
	// Parse the connection message.
	message := Message{}
	if err := receive(conn, &message); err != nil {
		return err
	}

	// Make sure it's an Announcement and extract the Nonce.
	data := AnnouncementMessage{}
	data.Nonce = s.Suite.Secret()
	if err := protobuf.Decode(message.Data, &data, nil); err != nil {
		return err
	}

	// Check the the message is properly signed by who it's
	// claiming to be from.
	nonce := data.Nonce
	if err := s.Verify(message, data.Id); err != nil {
		return err
	}

	// See if there's already a session for that Nonce and,
	// if not, start up a new one.
	forward, ok := s.Sessions[nonce.String()]
	if !ok {
		forward = NewSession(s.Context, nonce, nil, s.Done)
		s.Sessions[nonce.String()] = forward
	}

	// Finally, forward the connection to the proper Session.
	forward <- Connection{ data, conn }
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
			forward := NewSession(s.Context, nonce, conn, s.Done)
			s.Sessions[nonce.String()] = forward
		case nonce := <-s.Done:
			forward, ok := s.Sessions[nonce.String()]
			if ok {
				close(forward)
				delete(s.Sessions, nonce.String())
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
