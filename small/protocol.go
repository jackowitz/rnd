package main

import (
	"net"
	"github.com/dedis/crypto/poly"
)

type Protocol interface {
	NewSession(*Context, Nonce, net.Conn, chan<-Nonce) chan<-Connection
	NewLeaderSession(*Context, Nonce, net.Conn, chan<-Nonce) chan<-Connection
}

// We just use this as a factory, so we don't need any fields here. Maybe
// later we'll want to move the protocol data structures here though.
type SmallProtocol struct {}

// Creates a new session of the small group protocol and starts it running
// in a separate goroutine. The small group session is defined in small.go.
func (p *SmallProtocol) NewSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {

	conns := make([]net.Conn, context.N)
	broadcaster := &Broadcaster{ context, conns }

	session := &SmallSession{
		context,
		broadcaster,
		nonce,
		context.Suite.Secret(),
		new(poly.PriPoly),
		new(poly.PriShares),
		new(poly.PubPoly),
		make([]*poly.PriShares, context.N),
		make([]*poly.PubPoly, context.N),
	}

	for i := range session.shares {
		session.shares[i] = new(poly.PriShares)
		session.shares[i].Empty(session.Suite, session.K, session.N)
	}

	incoming := make(chan Connection)
	go session.Start(incoming, replyConn, done)

	return incoming
}

// For the small group protocol we don't have the notion of a leader.
func (p *SmallProtocol) NewLeaderSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {
	return p.NewSession(context, nonce, replyConn, done)
}

// Again, just a factory, this time for the scalable protocol.
type ScalableProtocol struct {}

func (p *ScalableProtocol) NewSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {

	scalable := &ScalableSession{
		context,
		nonce,
		nil,
		context.Suite.Secret(),
		context.Suite.Point(),
		nil,
	}

	incoming := make(chan Connection)
	go scalable.Start(incoming, replyConn, done)

	return incoming
}

func (p *ScalableProtocol) NewLeaderSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {

	broadcaster := &Broadcaster{
		context,
		make([]net.Conn, context.N),
	}

	scalable := &ScalableLeaderSession{
		context,
		broadcaster,
		nonce,
		context.Suite.Secret(),
		context.Suite.Point(),
		nil,
		nil,
	}

	incoming := make(chan Connection)
	go scalable.Start(incoming, replyConn, done)

	return incoming

}
