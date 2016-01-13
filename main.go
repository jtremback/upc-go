package main

// poc cli
//
// Generate and store own identities
// Add and store peer identities
// Open and store channels
// Update channels
// Receive update and store
// Serve channel info
// Check channel info

// Alice makes opening transaction proposal
// Bob verifies it with Alice's signature
// Bob adds his signature, creates opening transaction
// Bank verifies it with both signatures

// Alice makes update transaction proposal
// Bob verifies it with Alice's signature and criteria
// He considers himself paid

// Bob adds his signature to update transaction
// Sends it to bank
// Bank checks both signatures

import (
	"bytes"
	"crypto/rand"
	"strings"
	// "encoding/binary"
	// "encoding/json"
	"errors"
	"fmt"
	"github.com/agl/ed25519"
	"github.com/golang/protobuf/proto"
	"github.com/jtremback/upc/buf"
	"github.com/jtremback/upc/memdb"
	"log"
)

const (
	PublicKeySize        = ed25519.PublicKeySize
	PrivateKeySize       = ed25519.PrivateKeySize
	SignatureSize        = ed25519.SignatureSize
	OpeningTxPayloadSize = 80
	UpdateTxPayloadSize  = 1
	ChannelIDSize        = 32
)

func main() {
	conditions := []*pb.UpdateTx_Condition{&pb.UpdateTx_Condition{
		PresetCondition: *proto.Uint32(1),
		Data:            *proto.String("key: crunk"),
	}}
	test := pb.UpdateTx{
		ChannelID:      *proto.String("shibby"),
		NetTransfer:    *proto.Int64(-34),
		SequenceNumber: *proto.Uint32(12),
		Fast:           *proto.Bool(true),
		Conditions:     conditions,
	}

	data, err := proto.Marshal(&test)
	if err != nil {
		log.Fatal("marshaling error: ", err)
	}

	wrapped := pb.Envelope{
		Type:       pb.Envelope_UpdateTx,
		Signature1: []byte{0},
		Payload:    data,
	}

	data, err = proto.Marshal(&wrapped)
	if err != nil {
		log.Fatal("marshaling error: ", err)
	}

	newTest := &pb.Envelope{}
	err = proto.Unmarshal(data, newTest)
	if err != nil {
		log.Fatal("unmarshaling error: ", err)
	}

	newerTest := &pb.UpdateTx{}
	err = proto.Unmarshal(newTest.Payload, newerTest)
	if err != nil {
		log.Fatal("unmarshaling error: ", err)
	}

	fmt.Println(newerTest)
	// Now test and newTest contain the same data.
	// if test.GetLabel() != newTest.GetLabel() {
	// 	log.Fatalf("data mismatch %q != %q", test.GetLabel(), newTest.GetLabel())
	// }
	// etc.
}

// func MakeIdentity(nick string) error {

// }

func getConditionalTransfer(lst pb.UpdateTx) int64 {
	// Sum up all conditional transfer amounts and add to net transfer
	var ct int64
	for _, v := range lst.Conditions {
		ct += v.ConditionalTransfer
	}

	return ct
}

func MakeUpdateTxProposal(nick string, chID string, amt uint32, db leveldb.DB) ([]byte, error) {
	ident := pb.Identity{}
	err := proto.Unmarshal(db.Get(makeLevelKey("identity", nick)), &ident)
	if err != nil {
		return nil, err
	}

	ch := pb.Channel{}
	err = proto.Unmarshal(db.Get(makeLevelKey("channel", chID)), &ch)
	if err != nil {
		return nil, err
	}

	lst := ch.LastUpdateTx
	nt := lst.NetTransfer

	// Check if we are pubkey1 or pubkey2 and add or subtract amt from net transfer
	switch ch.Me {
	case 1:
		nt += int64(amt)
	case 2:
		nt -= int64(amt)
	}

	ct := getConditionalTransfer(lst)

	// Check if the net transfer amount is still valid
	if ct+nt > int64(ch.OpeningTx.Amount1) || ct+nt < int64(ch.OpeningTx.Amount2) {
		return nil, errors.New("invalid amt")
	}

	// Make new update transaction
	utx := pb.UpdateTx{
		ChannelID:      chID,
		NetTransfer:    nt,
		SequenceNumber: lst.SequenceNumber + 1,
		Fast:           false,
	}

	// Serialize update transaction
	data, err := proto.Marshal(&utx)
	if err != nil {
		return nil, err
	}

	// Sign update transaction
	sig := ed25519.Sign(privateKey, message)

	// Make new envelope
	ev := pb.Envelope{
		Type:    pb.Envelope_UpdateTxProposal,
		Payload: data,
	}

	// Put signature in correct slot
	switch ch.Me {
	case 1:
		ev.Signature1 = sig
	case 2:
		ev.Signature2 = sig
	}

	// Serialize envelope
	data, err = proto.Marshal(&ev)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func ReceiveUpdateTxProposal(ev pb.Envelope) (uint32, error) {
	ch := pb.Channel{}
	err = proto.Unmarshal(db.Get(makeLevelKey("channel", chID)), &ch)
	if err != nil {
		return nil, err
	}

	// Read signature from correct slot
	switch ch.Me {
	case 1:
		sig := ev.Signature2
		pubkey := ch.OpeningTx.Pubkey2
	case 2:
		sig := ev.Signature1
		pubkey := ch.OpeningTx.Pubkey2
	}

	// Check signature
	if !ed25519.Verify(pubkey, ev.Payload, sig) {
		return nil, errors.New("invalid signature")
	}

	utx := pb.UpdateTx{}
	err = proto.Unmarshal(ev.Payload, &utx)
	if err != nil {
		return nil, err
	}

	lst := ch.LastUpdateTx
	nt := lst.NetTransfer

	switch ch.Me {
	case 1:
		amt := utx.NetTransfer - lst.NetTransfer
	case 2:
		amt := lst.NetTransfer - utx.NetTransfer
	}

	return amt, nil
}

func makeLevelKey(indexes ...string) []byte {
	return []byte(strings.Join(indexes, ":"))
}

func MakeKeypair() (*[PublicKeySize]byte, *[PrivateKeySize]byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}
