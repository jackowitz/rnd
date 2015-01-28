package main

import (
	"crypto/cipher"
	"fmt"
	"net"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
	"rnd/prefix"
)

type Server struct {
	// For handling nonce-related stuff.
	suite abstract.Suite
	random cipher.Stream

	// Session management stuff.
	sessions map[string] chan <-net.Conn
	done chan Nonce
}

// Returns an empty nonce for decoding into.
func (s *Server) NewNonce() Nonce {
	return s.suite.Secret()
}

// Returns a random nonce for identify a new session.
func (s *Server) NextNonce() Nonce {
	return s.suite.Secret().Pick(s.random)
}

// Creates and returns a new server, ready to be started.
func NewServer() *Server {

	suite := nist.NewAES128SHA256P256()
	random := random.Stream

	sessions := make(map[string]chan <-net.Conn)
	done := make(chan Nonce)

	return &Server{
		suite,
		random,
		sessions,
		done,
	}
}

// Helper for handling connections from peers within the
// protocol. Basically just keeps track of forwarding
// new connections to the proper session, creating it
// first if necessary.
func (s *Server) HandleConnection(conn net.Conn,
		context *Context) error {

	// Extract the nonce that identifies the session.
	buf, err := prefix.ReadPrefix(conn);
	if err != nil {
		return err
	}
	nonce := s.NewNonce()
	if err := nonce.Decode(buf); err != nil {
		return err
	}

	// See if there's already a session for that nonce;
	// if not, start up a new one and record it.
	forward, ok := s.sessions[nonce.String()]
	if !ok {
		forward = NewSession(context, nonce, nil, s.done)
		s.sessions[nonce.String()] = forward
	}

	// Forward the connection to the proper session.
	forward <- conn
	return nil
}

// This is where the bulk of the server work is done. Comments
// near the main loop should explain things nicely.
func (s *Server) Start(context *Context, requestsPort int) {

	// Start listening for connections from peers.
	incoming, err := Listen(context.Self().Addr)
	if err != nil {
		panic("ListenPeers: " + err.Error())
	}

	// Optionally listen for requests to start sessions.
	var requests <-chan net.Conn
	if requestsPort > 1024 {
		addr := fmt.Sprintf(":%d", requestsPort)
		requests, err = Listen(addr)
		if err != nil {
			panic("ListenRequests: " + err.Error())
		}
	}

	// The main server loop, multiplexes between connections from
	// peers in the protocol, from external initiation of requests
	// to spawn new sessions, and from notifications from sessions
	// that they have completed.
	for {
		select {
		case conn := <-incoming:
			if err := s.HandleConnection(conn, context); err != nil {
				panic("HandleConnection: " + err.Error())
			}
		case conn := <-requests:
			nonce := s.NextNonce()
			forward := NewSession(context, nonce, conn, s.done)
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
// on which that goroutine delivers accepted connections. The
// goroutine loops infinitely waiting for new connections.
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
