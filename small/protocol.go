package main

import (
	"net"
)

type Protocol interface {
	NewSession(*Context, Nonce, net.Conn, chan<-Nonce) chan<-Connection
	NewLeaderSession(*Context, Nonce, net.Conn, chan<-Nonce) chan<-Connection
}

type SmallProtocol struct {}

func (p *SmallProtocol) NewSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {
	return NewSmallSession(context, nonce, replyConn, done)
}

func (p *SmallProtocol) NewLeaderSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {
	return NewSmallSession(context, nonce, replyConn, done)
}

type ScalableProtocol struct {}

func (p *ScalableProtocol) NewSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {
	return NewScalableSession(context, nonce, replyConn, done)
}

func (p *ScalableProtocol) NewLeaderSession(context *Context, nonce Nonce,
		replyConn net.Conn, done chan<- Nonce) chan <-Connection {
	return NewScalableLeaderSession(context, nonce, replyConn, done)
}
