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
	// "bytes"
	"crypto/rand"
	"strings"
	// "encoding/binary"
	// "encoding/json"
	"errors"
	// "fmt"
	"github.com/agl/ed25519"
	"github.com/golang/protobuf/proto"
	// "github.com/jtremback/upc/memdb"
	"github.com/jtremback/upc/pb"
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
	conditions := []*pb.UpdateTx_Condition{{
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
}

func getConditionalTransfer(lst *pb.UpdateTx) int64 {
	// Sum up all conditional transfer amounts and add to net transfer
	var ct int64
	for _, v := range lst.Conditions {
		ct += v.ConditionalTransfer
	}

	return ct
}

func MakeUpdateTxProposal(amt uint32, ch *pb.Channel) (*pb.UpdateTx, error) {
	lst := ch.LastUpdateTx
	nt := lst.NetTransfer

	// Check if we are pubkey1 or pubkey2 and add or subtract amt from net transfer
	switch ch.Me {
	case 1:
		nt += int64(amt)
	case 2:
		nt -= int64(amt)
	}

	// Add conditional transfer
	nt += getConditionalTransfer(lst)

	// Check if the net transfer amount is still valid
	if nt > int64(ch.OpeningTx.Amount1) || nt < -int64(ch.OpeningTx.Amount2) {
		return nil, errors.New("invalid amt")
	}

	// Make new update transaction
	return &pb.UpdateTx{
		ChannelID:      ch.ChannelID,
		NetTransfer:    nt,
		SequenceNumber: lst.SequenceNumber + 1,
		Fast:           false,
	}, nil
}

func sliceTo64Byte(slice []byte) *[64]byte {
	var array [64]byte
	copy(array[:], slice[:64])
	return &array
}

func sliceTo32Byte(slice []byte) *[32]byte {
	var array [32]byte
	copy(array[:], slice[:32])
	return &array
}

func SignUpdateTxProposal(utx *pb.UpdateTx, ident *pb.Identity, ch *pb.Channel) (*pb.Envelope, error) {
	// Serialize update transaction
	data, err := proto.Marshal(utx)
	if err != nil {
		return nil, err
	}

	// Sign update transaction, convert signature to slice
	sig := ed25519.Sign(sliceTo64Byte(ident.Privkey), data)

	// Make new envelope
	ev := pb.Envelope{
		Type:    pb.Envelope_UpdateTxProposal,
		Payload: data,
	}
	// fmt.Println(ed25519.GenerateKey(rand.Reader))
	// Put signature in correct slot
	switch ch.Me {
	case 1:
		ev.Signature1 = sig[:]
	case 2:
		ev.Signature2 = sig[:]
	}

	return &ev, nil
}

// func MakeOpeningProposal(amt uint32, ident *pb.Identity, ch *pb.Channel) ()

// // Serialize envelope
// data, err = proto.Marshal(&ev)
// if err != nil {
// 	return nil, err
// }

// ch := pb.Channel{}
// err := proto.Unmarshal(db.Get(makeLevelKey("channel", chID)), &ch)
// if err != nil {
// 	return nil, err
// }

func VerifyUpdateTxProposal(ev *pb.Envelope, ch *pb.Channel) (uint32, error) {
	var pubkey [32]byte
	var sig [64]byte

	// Read signature from correct slot
	// Copy signature and pubkey
	switch ch.Me {
	case 1:
		pubkey = *sliceTo32Byte(ch.OpeningTx.Pubkey2)
		sig = *sliceTo64Byte(ev.Signature2)
	case 2:
		pubkey = *sliceTo32Byte(ch.OpeningTx.Pubkey1)
		sig = *sliceTo64Byte(ev.Signature1)
	}

	// Check signature
	if !ed25519.Verify(&pubkey, ev.Payload, &sig) {
		return 0, errors.New("invalid signature")
	}

	utx := pb.UpdateTx{}
	err := proto.Unmarshal(ev.Payload, &utx)
	if err != nil {
		return 0, err
	}

	lst := ch.LastUpdateTx

	// Check last sequence number
	if lst.SequenceNumber+1 != utx.SequenceNumber {
		return 0, errors.New("invalid sequence number")
	}

	// Get amount depending on if we are party 1 or party 2
	var amt uint32
	switch ch.Me {
	case 1:
		amt = uint32(lst.NetTransfer - utx.NetTransfer)
	case 2:
		amt = uint32(utx.NetTransfer - lst.NetTransfer)
	}

	return amt, nil
}

func makeLevelKey(indexes ...string) []byte {
	return []byte(strings.Join(indexes, ":"))
}

func MakeKeypair() (*[PublicKeySize]byte, *[PrivateKeySize]byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}
