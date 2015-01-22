package main

import (
	"net"
	"time"
	"github.com/dedis/crypto/protobuf"
)

type Broadcaster struct {
	Conns []net.Conn
}

// Higher order function to handle broadcasting a type of message
// to all peers. Take a contructor to make the messages based on
// the id of the peer.
func (b *Broadcaster) Broadcast(constructor func(int)interface{}) error {

	for i, conn := range b.Conns {
		if conn == nil { continue }
		message := constructor(i)
		_, err := WritePrefix(conn, protobuf.Encode(message))
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadOne(conn net.Conn, structPtr interface{},
		cons protobuf.Constructors) error {

	timeout := 2 * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	raw, err := ReadPrefix(conn)
	if err != nil {
		return err
	}
	err = protobuf.Decode(raw, structPtr, cons)
	if err != nil {
		return err
	}
	return nil
}

// Higher order function for reading the same type of message from all
// of our peers. Spawns a goroutine for each peer and delivers
// the results on the returned channel.
func (b *Broadcaster) ReadAll(constructor func()interface{},
		cons protobuf.Constructors) <-chan interface{} {

	results := make(chan interface{}, len(b.Conns))
	for _, conn := range b.Conns {
		if conn == nil { continue }

		message := constructor()
		go func(conn net.Conn, message interface{}) {
			if err := ReadOne(conn, message, cons); err != nil {
				results <- nil
			} else {
				results <- message
			}
		}(conn, message)
	}
	return results
}
