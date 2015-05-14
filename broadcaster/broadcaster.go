package broadcaster

import (
	"fmt"
	"github.com/dedis/protobuf"
	"net"
	"rnd/prefix"
	"time"
)

// A Broadcaster is an abstraction enabling interaction with a set
// of connections as a single object.
type Broadcaster struct {
	Conns []net.Conn
}

// Create a new broadcaster wrapping the provided set of connections.
func NewBroadcaster(conns []net.Conn) *Broadcaster {
	return &Broadcaster{conns}
}

// Broadcast a message to all connections wrapped by this broadcaster.
// Since it's possible that each connection should get a different
// variant of the message, the function takes a constructor which it
// then uses for creating the messages.
func (b *Broadcaster) Broadcast(constructor func(int)interface{}) error {

	for i, conn := range b.Conns {
		if conn == nil { continue }

		message := constructor(i)
		data, _ := protobuf.Encode(message)
		_, err := prefix.WritePrefix(conn, data)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadOne(conn net.Conn, structPtr interface{},
		cons protobuf.Constructors) error {

	timeout := 2 * time.Second
	return ReadOneTimeout(conn, structPtr, cons, timeout)
}

func ReadOneTimeout(conn net.Conn, structPtr interface{},
		cons protobuf.Constructors, timeout time.Duration) error {

	conn.SetReadDeadline(time.Now().Add(timeout))

	raw, err := prefix.ReadPrefix(conn)
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
				fmt.Println("ReadOne: " + err.Error())
				results <- nil
			} else {
				results <- message
			}
		}(conn, message)
	}
	return results
}
