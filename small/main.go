package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	//"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/protobuf"
	"github.com/dedis/crypto/random"
	"rnd_tcp/stopwatch"
)

const testing = false
const debug = true

type Nonce abstract.Secret

var aSecret abstract.Secret
var tSecret = reflect.TypeOf(&aSecret).Elem()

var aPoint abstract.Point
var tPoint = reflect.TypeOf(&aPoint).Elem()

var aNonce Nonce
var tNonce = reflect.TypeOf(&aNonce).Elem()

type MessageType int
const (
	MSG_ANNOUNCE MessageType = iota
	MSG_SHARE_COMMIT
	MSG_STATUS
	MSG_SHARE
)

type Message struct {
	Data []byte
	Signature []byte
}

func send(w io.Writer, message interface{}) error {
	data := protobuf.Encode(message)
	length := len(data)
	buf := make([]byte, length+2)
	binary.LittleEndian.PutUint16(buf[:2], uint16(length))
	copy(buf[2:], data)
	_, err := w.Write(buf)
	return err
}

func receive(r io.Reader, structPtr interface{}) error {
	lenbuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenbuf); err != nil {
		return err
	}
	length := binary.LittleEndian.Uint16(lenbuf)
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return protobuf.Decode(buf, structPtr, nil)
}

type ShareCommitMessage struct {
	Nonce Nonce

	Index, Source int
	Share abstract.Secret
	Commitment interface{} // poly.PubPoly
}

type ShareMessage struct {
	Nonce Nonce

	Source int
	Shares []abstract.Secret
}

type Status int
const (
	SUCCESS Status = iota
	FAILURE
)

type StatusMessage struct {
	Nonce Nonce

	Source int
	Status Status
}

func (s *Session) GenerateRandom() (abstract.Secret, *stopwatch.Stopwatch) {

	// Record performance/debug timings.
	stopwatch := stopwatch.NewStopwatch()

	stopwatch.Start()
	s.GenerateInitialShares()
	stopwatch.Stop("PickSplitCommit")

	stopwatch.Start()
	if err := s.SendShareCommitMessages(); err != nil {
		panic("SendShareCommitMessages: " + err.Error())
	}
	stopwatch.Stop("SendCommits")

	stopwatch.Start()
	status := SUCCESS
	if err := s.ReceiveShareCommitMessages(); err != nil {
		fmt.Println("FAILURE")
		status = FAILURE
	}
	stopwatch.Stop("ReceiveCommits")

	stopwatch.Start()
	if err := s.SendStatusMessages(status); err != nil {
		panic("SendStatusMessages: " + err.Error())
	}
	stopwatch.Stop("SendStatus")

	stopwatch.Start()
	if err := s.ReceiveStatusMessages(); err != nil {
		panic("ReceiveStatusMessages: " + err.Error())
	}
	stopwatch.Stop("ReceiveStatus")

	stopwatch.Start()
	if err := s.SendShareMessages(); err != nil {
		panic("SendShareMessages: " + err.Error())
	}
	stopwatch.Stop("SendShares")

	stopwatch.Start()
	if err := s.ReceiveShareMessages(); err != nil {
		panic("ReceiveShareMessages: " + err.Error())
	}
	stopwatch.Stop("ReceiveShares")

	// XOR all the individual secrets together
	stopwatch.Start()
	value, err :=  s.CombineShares()
	if err != nil {
		panic("CombineShares: " + err.Error())
	}
	stopwatch.Stop("CombineShares")

	// XXX: this approach is group-dependent, maybe
	// just want to return a []byte
	return value, stopwatch
}

type AnnouncementMessage struct {
	Nonce Nonce
	Id int
}

type Connection struct {
	Message AnnouncementMessage
	Conn net.Conn
}

const timeout = 3*time.Second

func (s *Session) Start(connChan <-chan Connection,
		replyConn net.Conn, close chan<- Nonce) {

	for i := s.Mine + 1; i < s.N; i++ {
		conn, err := net.DialTimeout("tcp", s.Peers[i].Addr, timeout)
		if err != nil {
			format := "Unable to connect to server at %s"
			panic(fmt.Sprintf(format, s.Peers[i].Addr))
		}
		data := AnnouncementMessage{ s.Nonce, s.Mine }
		message := s.Sign(&data)
		if err := send(conn, &message); err != nil {
			panic("announcement: " + err.Error())
		}
		s.Conns[i] = conn
	}

	// wait for connection from all servers with id less than ours
	for i := 0; i < s.Mine; i++ {
		connection := <- connChan
		s.Conns[connection.Message.Id] = connection.Conn
	}

	// no more connections for this session, notify
	// the main loop to clean up the map
	close <- s.Nonce

	// everyone's all wired up, so start the protocol
	value, stopwatch := s.GenerateRandom()
	if debug {
		format := "[%d, %d] Times: %s\n"
		fmt.Printf(format, s.N, s.K, stopwatch)
		fmt.Printf("Value: %s\n", value.String())
	}
	if replyConn != nil {
		if _, err := replyConn.Write(value.Encode()); err != nil {
			panic("reply send: " + err.Error())
		}
	}

	if replyConn != nil {
		if err := replyConn.Close(); err != nil {
			panic("reply close: " + err.Error())
		}
	}
}

// Listen for incoming TCP connections on the provided address.
func main() {
	n := flag.Int("n", 3, "number of servers")
	k := flag.Int("k", 3, "share threshold")
	flag.Parse()
	if flag.NArg() < 1 {
		panic("must specify server index")
	}
	id, err := strconv.Atoi(flag.Arg(0))
	if err != nil {
		panic("server index must be an integer")
	}

	// Swappable crypto modules.
	suite := nist.NewAES128SHA256P256()
	random := random.Stream

	// Use a local setup for now.
	contextRandom := abstract.HashStream(suite, []byte("test"), nil)
	config := NewLocalPeerConfig(suite, contextRandom, id, *n, *k)

	context := NewContext(suite, random, config)
	NewServer(context).Start()
}
