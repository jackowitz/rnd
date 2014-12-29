package main

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/anon"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/poly"
	"github.com/dedis/crypto/protobuf"
	"github.com/dedis/crypto/random"
)

const testing = false
const debug = false

type Server struct {
	Id int
	Address string
	PrivKey abstract.Secret
	PubKey abstract.Point
}

type Context struct {
	Suite abstract.Suite
	Random cipher.Stream
	Servers []Server
	Mine, N, K int
}

// Generate a new context. Populate it with everyone's private
// keys for now, to make testing easier.
func NewContext(suite abstract.Suite, random cipher.Stream,
		mine, n, k int) *Context {

	context := Context{ suite, random, make([]Server, n), mine, n, k }
	for i := 0; i < n; i++ {
		address := fmt.Sprintf("localhost:%d", 8080+i)
		x := suite.Secret().Pick(random)
		X := suite.Point().Mul(nil, x)
		context.Servers[i] = Server{i, address, x, X}
	}
	return &context
}

type Nonce abstract.Secret

var aSecret abstract.Secret
var tSecret = reflect.TypeOf(&aSecret).Elem()

var aPoint abstract.Point
var tPoint = reflect.TypeOf(&aPoint).Elem()

var aNonce Nonce
var tNonce = reflect.TypeOf(&aNonce).Elem()

func (c *Context) NextNonce() Nonce {
	return c.Suite.Secret().Pick(c.Random)
}

func (c *Context) Self() *Server {
	return &c.Servers[c.Mine]
}

type Message struct {
	Data []byte
	Signature []byte
}

func (context *Context) Sign(structPtr interface{}) Message {
	self := context.Self()
	data := protobuf.Encode(structPtr)
	signature := anon.Sign(context.Suite, context.Random, data,
			anon.Set{self.PubKey}, nil, 0, self.PrivKey)
	return Message{data, signature}
}

func (context *Context) Verify(message Message, server int) error {
	key := anon.Set{context.Servers[server].PubKey}
	_, err := anon.Verify(context.Suite, message.Data, key,
			nil, message.Signature)
	return err
}

// The send() and receive() functions are helpers for working
// with the protobuf encoded data. They append/extract the overall
// message length to allow for easy sending over the wire.
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

type msgShare struct {
	Index int
	Share abstract.Secret
	Commitment interface{} // poly.PubPoly
	// XXX add Nonce to prevent replay attack
}

type Status int
const (
	SUCCESS Status = iota
	FAILURE
)

type msgStatus struct {
	Status Status
}

type debugGenerate struct {
	PickSplitCommit time.Duration
	SendCommits, RecvCommits time.Duration
	SendStatus, RecvStatus time.Duration
	SendShares, RecvShares time.Duration
	Combine time.Duration
}

func (d debugGenerate) String() string {
	format := "\tPickSplitCommit: %s\n" +
		"\tSendCommits: %s\n" +
		"\tRecvCommits: %s\n" +
		"\tSendStatus: %s\n" +
		"\tRecvStatus: %s\n" +
		"\tSendShares: %s\n" +
		"\tRecvShares: %s\n" +
		"\tCombine: %s"
	return fmt.Sprintf(format, d.PickSplitCommit,
		d.SendCommits, d.RecvCommits, d.SendStatus,
		d.RecvStatus, d.SendShares, d.RecvShares, d.Combine)
}

func (session *Session) GenerateRandom() (abstract.Secret, debugGenerate) {
	debugStats := debugGenerate{}

	context := session.Context
	conns := session.Conns

	suite := context.Suite
	random := context.Random

	// pick our secret r_i value randomly and split it into
	// n shares, k of which are needed to recover r_i
	start := time.Now()
	ri := suite.Secret().Pick(random)
	ai := new(poly.PriPoly).Pick(suite, context.K, ri, random)
	si := new(poly.PriShares).Split(ai, context.N)
	pi := new(poly.PubPoly).Commit(ai, nil)
	debugStats.PickSplitCommit = time.Since(start)

	// send share and commitment to each peer
	start = time.Now()
	for i := range conns {
		if i == context.Mine {
			continue
		}
		share := msgShare{ i, si.Share(i), pi }
		message := context.Sign(&share)
		if err := send(conns[i], &message); err != nil {
			panic("sending share: " + err.Error())
		}
	}
	debugStats.SendCommits = time.Since(start)

	// initialize the shares
	start = time.Now()
	shares := make([]*poly.PriShares, context.N)
	for i := range shares {
		shares[i] = new(poly.PriShares)
		shares[i].Empty(suite, context.K, context.N)
	}
	shares[context.Mine] = si

	// hold on to the share messages to redistribute later
	messages := make([]Message, context.N)
	share := &msgShare{ context.Mine, si.Share(context.Mine), pi }
	messages[context.Mine] = context.Sign(share)

	// listen for as many shares as possible
	for i := range conns {
		if i == context.Mine {
			continue
		}
		message := Message{}
		if err := receive(conns[i], &message); err != nil {
			panic(err.Error())
		}
		if err := context.Verify(message, i); err != nil {
			panic(err.Error())
		}
		commitment := new(poly.PubPoly)
		commitment.Init(suite, context.K, nil)
		share := msgShare{ 0, suite.Secret(), commitment}
		if err := protobuf.Decode(message.Data, &share, nil); err != nil {
			panic(err.Error())
		}
		if share.Index != context.Mine {
			format := "server %d sent %d's share?!"
			panic(fmt.Sprintf(format, i, share.Index))
		}
		if !commitment.Check(context.Mine, share.Share) {
			panic(fmt.Sprintf("share from %d doesn't verify", i))
		}
		messages[i] = message
		shares[i].SetShare(context.Mine, share.Share)
	}
	debugStats.RecvCommits = time.Since(start)

	// XXX just hardcode success for now
	start = time.Now()
	status := msgStatus { SUCCESS }
	for i := range conns {
		if i == context.Mine {
			continue
		}
		if err := send(conns[i], &status); err != nil {
			panic("send status: " + err.Error())
		}
	}
	debugStats.SendStatus = time.Since(start)

	// make sure everybody reports SUCCESS
	start = time.Now()
	for i := range conns {
		if i == context.Mine {
			continue
		}
		if err := receive(conns[i], &status); err != nil {
			panic("receive status: " + err.Error())
		}
		if status.Status != SUCCESS {
			panic(fmt.Sprintf("got FAILURE from %d", i))
			// XXX clean up (preferably using defer)
		}
	}
	debugStats.RecvStatus = time.Since(start)

	// got SUCCESS from everybody, so release our shares
	start = time.Now()
	for i := range conns {
		if i == context.Mine {
			continue
		}
		for j := range messages {
			send(conns[i], &messages[j])
		}
	}
	debugStats.SendShares = time.Since(start)

	// listen for incoming shares from everybody
	// XXX there's some code duplication here but it's not exact
	start = time.Now()
	for i := range conns {
		if i == context.Mine {
			continue
		}
		for j := range messages {
			message := Message{}
			if err := receive(conns[i], &message); err != nil {
				panic(err.Error())
			}
			if j == context.Mine {
				continue
			}
			if err := context.Verify(message, j); err != nil {
				panic(err.Error())
			}
			commitment := new(poly.PubPoly)
			commitment.Init(suite, context.K, nil)
			share := msgShare{ 0, suite.Secret(), commitment}
			if err := protobuf.Decode(message.Data, &share, nil); err != nil {
				panic(err.Error())
			}
			if !commitment.Check(i, share.Share) {
				panic(fmt.Sprintf("share from %d doesn't verify", i))
			}
			shares[j].SetShare(i, share.Share)
		}
	}
	debugStats.RecvShares = time.Since(start)

	// XOR all the individual secrets together
	start = time.Now()
	result := make([]byte, suite.SecretLen())
	for i := range shares {
		recovered := shares[i].Secret()
		bytes := recovered.Encode()
		for i := 0; i < suite.SecretLen(); i++ {
			result[i] ^= bytes[i]
		}
	}
	debugStats.Combine = time.Since(start)

	// XXX: this approach is group-dependent, maybe
	// just want to return a []byte
	value := suite.Secret()
	if err := value.Decode(result); err != nil {
		panic("final decode: " + err.Error())
	}
	return value, debugStats
}

type Session struct {
	Context *Context
	Nonce Nonce
	Values int
	Conns []net.Conn
}

type msgSession struct {
	Nonce Nonce
	Values int
	Id int
}

type Connection struct {
	Message msgSession
	Conn net.Conn
}

const timeout = 3*time.Second

func (session *Session) Start(connChan <-chan Connection,
		replyConn net.Conn, close chan<- Nonce) {

	start := time.Now()
	context := session.Context
	for i := context.Mine + 1; i < context.N; i++ {
		server := context.Servers[i]
		conn, err := net.DialTimeout("tcp", server.Address, timeout)
		if err != nil {
			format := "Unable to connect to server at %s"
			panic(fmt.Sprintf(format, server.Address))
		}
		data := msgSession{ session.Nonce, session.Values, context.Mine }
		message := context.Sign(&data)
		if err := send(conn, &message); err != nil {
			panic("announcement: " + err.Error())
		}
		session.Conns[i] = conn
	}

	// wait for connection from all servers with id less than ours
	for i := 0; i < context.Mine; i++ {
		connection := <- connChan
		session.Conns[connection.Message.Id] = connection.Conn
	}
	connect := time.Since(start)
	if debug {
		fmt.Printf("[%d, %d] Setup: %s\n", context.N, context.K, connect)
	}

	// no more connections for this session, notify
	// the main loop to clean up the map
	close <- session.Nonce

	// everyone's all wired up, so start the protocol
	for i := 0; i < session.Values; i++ {
		start = time.Now()
		value, debugStats := session.GenerateRandom()
		generate := time.Since(start)
		if debug && i == 0 {
			format := "[%d, %d] Generate: %s {\n%s\n}\n"
			fmt.Printf(format, context.N, context.K, generate, debugStats)
		}
		if replyConn != nil {
			if _, err := replyConn.Write(value.Encode()); err != nil {
				panic("reply send: " + err.Error())
			}
		}
	}
	if replyConn != nil {
		if err := replyConn.Close(); err != nil {
			panic("reply close: " + err.Error())
		}
	}
}

// Starts a new session in the given context. The session is identified
// by the provided nonce and produces <values> random values.
// Returns immediately with a channel on which subsequent connections
// to the session are delivered but spawns a new goroutine to run
// the actual session.
func (context *Context) NewSession(nonce Nonce, values int, replyConn net.Conn,
		closeChan chan<- Nonce) chan <-Connection {

	conns := make([]net.Conn, len(context.Servers))
	session := &Session{ context, nonce, values, conns }

	connChan := make(chan Connection)
	go session.Start(connChan, replyConn, closeChan)
	return connChan
}

func listen(address string, connChan chan<- net.Conn) error {
	listen, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	go func(listen net.Listener, connChan chan<- net.Conn) {
		for {
			conn, err := listen.Accept()
			if err != nil {
				continue
			}
			connChan <- conn
		}
	}(listen, connChan)
	return nil
}

// Request format: GENERATE <COUNT> RND/1.0\r\n
// XXX can definitely do this more elegantly
func parseRequest(conn net.Conn) (int, error) {
	reader := bufio.NewReader(conn)
	if buf, err := reader.ReadSlice(' '); err != nil {
		return -1, err
	} else {
		if strings.Trim(string(buf), " ") != "GENERATE" {
			return -1, errors.New("Invalid Request Method")
		}
	}
	buf, err := reader.ReadSlice(' ')
	if err != nil {
		return -1, err
	}
	values, err := strconv.Atoi(strings.Trim(string(buf), " "))
	if err != nil {
		return -1, err
	}
	// XXX protocol and version
	return values, nil
}

func startServer(context *Context) {

	// keep track of which sessions we've already started
	// XXX better key for the map, needs == and != operators
	sessions := make(map[string]chan <-Connection)

	// sessions signal when they are done accepting connections
	// by writing the session nonce to this channel
	// XXX actually handle this channel in select loop
	closeChan := make(chan Nonce)

	// listen for connections from other servers in the group
	internalConnChan := make(chan net.Conn)
	address := context.Self().Address
	if err := listen(address, internalConnChan); err != nil {
		panic("listen: " + err.Error())
	}

	// listen for requests to generate numbers
	externalConnChan := make(chan net.Conn)
	address = ":7999" // XXX parameterize
	if context.Mine == 0 {
		if err := listen(address, externalConnChan); err != nil {
			panic("listen: " + err.Error())
		}
	}

	for {
		select { // XXX clean this select up
		case conn := <-internalConnChan:
			// forward all subsequent connections based on
			// nonce, starting a new session if necessary
			message := Message{}
			if err := receive(conn, &message); err != nil {
				panic("receive connection: " + err.Error())
			}
			data := msgSession{}
			data.Nonce = context.Suite.Secret()
			if err := protobuf.Decode(message.Data, &data, nil); err != nil {
				panic(err.Error())
			}
			nonce := data.Nonce
			if err := context.Verify(message, data.Id); err != nil {
				panic(err.Error())
			}
			connChan, ok := sessions[nonce.String()]
			if !ok {
				connChan = context.NewSession(nonce, data.Values, nil, closeChan)
				sessions[nonce.String()] = connChan
			}
			connChan <- Connection{ data, conn }
		case conn := <-externalConnChan:
			nonce := context.NextNonce()
			values, err := parseRequest(conn)
			if err != nil {
				panic("request: " + err.Error())
			}
			connChan := context.NewSession(nonce, values, conn, closeChan)
			sessions[nonce.String()] = connChan
		case nonce := <-closeChan:
			connChan, ok := sessions[nonce.String()]
			if ok {
				close(connChan)
			}
			delete(sessions, nonce.String())
		}
	}
}

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

	// crypto setup for testing
	suite := nist.NewAES128SHA256P256()
	random := random.Stream

	if testing {
		seed := []byte(fmt.Sprintf("secret%d", id))
		random = abstract.HashStream(suite, seed, nil)
	}

	// everyone generates same context for testing
	contextRandom := abstract.HashStream(suite, []byte("test"), nil)
	context := NewContext(suite, contextRandom, id, *n, *k)
	context.Random = random

	startServer(context)
}
