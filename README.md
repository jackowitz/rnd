# rnd
Unbiasable Distributed Randomness Protocols

#### Dependencies
```
go get github.com/dedis/crypto
go get github.com/dedis/protobuf
cd $GOPATH/src/github.com/dedis/protobuf
git fetch
git checkout cleanup
```
#### Running Locally
Within each protocol directory there is a ```local.sh``` script that
handles building the executable and starting/stopping a local instance
of the protocol.
The ```./local.sh start``` command takes two positional arguments
specifying the ```k``` and ```n``` values, respectively.

There are some important differences between the small and scalable
protocols in terms of design. ```local.sh start 5 3``` for the small
protocol, for example, starts ```5``` clients locally, with client
```i``` claiming port ```8000 + i```.
Just running ```local.sh start n k```, however, does not actually
start the protocol.
Instead, client ```0``` also listens on port ```7999``` for incoming
requests to generate a random value.
These requests are as simple as it gets:
```nc localhost 7999``` begins a protocol run, and returns the
generated value to the requester.
This design allows the clients to serve multiple requests
concurrently, as independent sessions.
Since the clients in the small protocol continue to listen for
requests, ```local.sh stop``` must be run to tear everything
down.

The scalable protocol's ```local.sh start 5 3```, on the other
hand, actually performs a single run of the protocol. In the
scalable design, client ```0``` acts as the leader and initiates
the lottery protocol. The scalable protocol additionally
introduces the ```-adversary``` flag to control how many of
the clients fail to correctly reveal their secret in the
final step; by default, ```local.sh``` configures ```k```
clients as adversaries.

#### Logging/Output
The included ```local.sh``` scripts redirect each client's output
to a file in the ```logs``` directory. By default, timing measurements
are recorded for each step of the protocol, but this can be easily
extended with additional ```stopwatch``` calls.
