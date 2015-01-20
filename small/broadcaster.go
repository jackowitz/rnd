package main

import (
	"net"
	"time"
	"github.com/dedis/crypto/protobuf"
)

type Broadcaster struct {
	*Context
	Conns []net.Conn
}

// Higher order function to handle broadcasting a type of message
// to all peers. Take a contructor to make the messages based on
// the id of the peer.
func (b *Broadcaster) Broadcast(constructor func(int)interface{}) error {

	for i, conn := range b.Conns {
		if b.IsMine(i) {
			continue
		}
		data := constructor(i)
		message := &Message{ b.Mine, protobuf.Encode(data), nil }
		b.Sign(message)
		raw := protobuf.Encode(message)
		if _, err := WritePrefix(conn, raw); err != nil {
			return err
		}
	}
	return nil
}

func (b *Broadcaster) ReadOne(conn net.Conn, constructor func()interface{},
		verify bool, results chan<- interface{}) {

	// XXX should probably pull this out
	cons := protobuf.Constructors{
		tSecret: func()interface{} { return b.Suite.Secret() },
		tNonce: func()interface{} { return b.Suite.Secret() },
	}

	timeout := 2 * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	raw, err := ReadPrefix(conn)
	if err != nil {
		results <- nil
	}
	wrapper := new(Message)
	err = protobuf.Decode(raw, wrapper, nil)
	if err != nil {
		results <- nil
	}
	if err := b.Verify(wrapper); err != nil {
		results <- nil
	}
	data := wrapper.Data
	message := constructor()
	err = protobuf.Decode(data, message, cons)
	if err != nil {
		results <- nil
	}
	results <- message
}

// Higher order function for reading the same type of message from all
// of our peers. Spawns a goroutine for each peer and delivers
// the results on the returned channel.
func (b *Broadcaster) ReadAll(cons func()interface{},
		verify bool) <-chan interface{} {

	results := make(chan interface{}, b.N)
	for i, conn := range b.Conns {
		if b.IsMine(i) { continue }
		go b.ReadOne(conn, cons, verify, results)
	}
	return results
}

