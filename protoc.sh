# protoc ./wire/wire.proto --go_out ./ && protoc $GOPATH/src/github.com/jtremback/upc/peer/peer.proto --go_out $GOPATH/src -I $GOPATH/src && protoc $GOPATH/src/github.com/jtremback/upc/escrow/escrow.proto --go_out $GOPATH/src -I $GOPATH/src
#
protoc ./wire/wire.proto --go_out ./ && protoc $GOPATH/src/github.com/jtremback/upc/schema/schema.proto --go_out $GOPATH/src -I $GOPATH/src