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
Each protocol (small/scalable) has a ```local.sh``` script that handles
building the executable and starting/stopping a local instance of the protocol.
The ```./local.sh start``` command takes two positional arguments specifying the
```k``` and ```n``` values, respectively.
