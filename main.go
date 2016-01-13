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

func MakeUpdateTxProposal(nick string, chID string, amt uint32, db leveldb.DB) (*pb.UpdateTx, error) {
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

	up := ch.UpdateTxs[0]

	// Sum up all the possible conditional transfer amounts and add to net transfer
	nt := up.NetTransfer
	for _, v := range up.Conditions {
		nt += v.ConditionalTransfer
	}

	// Check if we are pubkey1 or pubkey2 and add or subtract amt from net transfer
	if bytes.Compare(ident.Pubkey, ch.OpeningTx.Pubkey1) == 0 {
		nt += int64(amt)
	} else if bytes.Compare(ident.Pubkey, ch.OpeningTx.Pubkey2) == 0 {
		nt -= int64(amt)
	} else {
		return nil, errors.New("this channel does not belong to this identity")
	}

	// Check if the net transfer amount is still valid
	if nt > int64(ch.OpeningTx.Amount1) || nt < int64(ch.OpeningTx.Amount2) {
		return nil, errors.New("invalid amt")
	}

	utx := pb.UpdateTx{
		ChannelID:      chID,
		NetTransfer:    nt,
		SequenceNumber: up.SequenceNumber + 1,
		Fast:           false,
	}

	return &utx, nil
}

// // Look up corresponding channel in db
// // Verify sig using pubkey from db
// func VerifyUpdateTxProposal(ev pb.Envelope, db leveldb.DB) (pb.UpdateTx, err) {
// 	tx := pb.UpdateTx{}
// 	err = proto.Unmarshal(ev.Payload, &tx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ch := pb.Channel{}
// 	err = proto.Unmarshal(db.Get(tx.ChannelID), &ch)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if !ed25519.Verify(ch.Pubkey1, ev.Payload, ev.Signature1) {
// 		return errors.New("signature is invalid")
// 	}

// 	return tx, nil
// }

// // Look up corresponding channel in db
// // Verify sig using pubkey from db
// func VerifyUpdateTx(ev pb.Envelope, db leveldb.DB) (pb.UpdateTx, err) {
// 	tx := pb.UpdateTx{}
// 	err = proto.Unmarshal(ev.Payload, &tx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ch := pb.Channel{}
// 	err = proto.Unmarshal(db.Get(tx.ChannelID), &ch)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if !ed25519.Verify(ch.Pubkey1, ev.Payload, ev.Signature1) {
// 		return errors.New("signature 1 is invalid")
// 	}

// 	if !ed25519.Verify(ch.Pubkey2, ev.Payload, ev.Signature2) {
// 		return errors.New("signature 2 is invalid")
// 	}

// 	return tx, nil
// }

// func VerifyOpeningTx(ev, db) {
// 	tx := pb.UpdateTx{}
// 	err = proto.Unmarshal(ev.Payload, &tx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ch := pb.Channel{}
// 	err = proto.Unmarshal(db.Get(tx.ChannelID), &ch)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if !ed25519.Verify(ch.Pubkey1, ev.Payload, ev.Signature1) {
// 		return errors.New("signature 1 is invalid")
// 	}

// 	if !ed25519.Verify(ch.Pubkey2, ev.Payload, ev.Signature2) {
// 		return errors.New("signature 2 is invalid")
// 	}

// 	return tx, nil
// }

// func VerifyOpeningTxProposal(ev, db) {

// }

// // func main() {
// // 	db := leveldb.NewDB()
// // 	MakeIdentity("faulkner", db)
// // 	db.Print()
// // }

func makeLevelKey(indexes ...string) []byte {
	return []byte(strings.Join(indexes, ":"))
}

func MakeKeypair() (*[PublicKeySize]byte, *[PrivateKeySize]byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// func MakeIdentity(
// 	nick string,
// 	pubkey [PublicKeySize]byte,
// 	privkey [PrivateKeySize]byte,
// 	db *leveldb.DB,
// ) error {
// 	k := makeLevelKey("identity", nick)
// 	if db.Get(k) != nil {
// 		return errors.New("an identity with that nickname already exists")
// 	}

// 	id := Identity{
// 		Nickname: nick,
// 		Pubkey:   *pubkey,
// 		Privkey:  *privkey,
// 	}

// 	jid, err := json.Marshal(&id)
// 	if err != nil {
// 		return err
// 	}

// 	db.Set(k, jid)

// 	return nil
// }

// func AddPeer(nick string, pubkey [PublicKeySize]byte, db *leveldb.DB) error {
// 	k := makeLevelKey("peer", nick)
// 	if db.Get(k) != nil {
// 		return errors.New("a peer with that nickname already exists")
// 	}

// 	peer := Peer{
// 		Nickname: nick,
// 		Pubkey:   pubkey,
// 	}

// 	jpeer, err := json.Marshal(&peer)
// 	if err != nil {
// 		return err
// 	}

// 	db.Set(k, jpeer)

// 	return nil
// }
