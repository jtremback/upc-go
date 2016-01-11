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
	"encoding/json"
	"errors"
	// "fmt"
	"github.com/agl/ed25519"
	"github.com/jtremback/upc/memdb"
)

const (
	PublicKeySize        = ed25519.PublicKeySize
	PrivateKeySize       = ed25519.PrivateKeySize
	SignatureSize        = ed25519.SignatureSize
	OpeningTxPayloadSize = 80
	ChannelIDSize        = 32
)

type OpeningTx struct {
	ChannelID  [ChannelIDSize]byte
	Pubkey1    [PublicKeySize]byte
	Pubkey2    [PublicKeySize]byte
	Amount1    uint32
	Amount2    uint32
	HoldPeriod uint64
	Signature1 [SignatureSize]byte
	Signature2 [SignatureSize]byte
}

type UpdateTx struct {
	ChannelID      [ChannelIDSize]byte
	NetTransfer    int64
	SequenceNumber uint32
	Fast           bool
	Signature1     [SignatureSize]byte
	Signature2     [SignatureSize]byte
}

type Channel struct {
	ChannelID [ChannelIDSize]byte
	OpeningTx
	UpdateTxs []UpdateTx
}

type Identity struct {
	Nickname string
	Pubkey   [PublicKeySize]byte
	Privkey  [PrivateKeySize]byte
	Channels [][ChannelIDSize]byte
}

type Peer struct {
	Nickname string
	Pubkey   [PublicKeySize]byte
	Channels [][ChannelIDSize]byte
}

func main() {
	db := leveldb.NewDB()
	MakeIdentity("faulkner", db)
	db.Print()
}

func makeLevelKey(indexes ...string) []byte {
	return []byte(strings.Join(indexes, ":"))
}

func MakeKeypair() ([PublicKeySize]byte, [PrivateKeySize]byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func MakeIdentity(
	nick string,
	pubkey [PublicKeySize]byte,
	privkey [PrivateKeySize]byte,
	db *leveldb.DB,
) error {
	k := makeLevelKey("identity", nick)
	if db.Get(k) != nil {
		return errors.New("an identity with that nickname already exists")
	}

	id := Identity{
		Nickname: nick,
		Pubkey:   *pubkey,
		Privkey:  *privkey,
	}

	jid, err := json.Marshal(&id)
	if err != nil {
		return err
	}

	db.Set(k, jid)

	return nil
}

func AddPeer(nick string, pubkey [PublicKeySize]byte, db *leveldb.DB) error {
	k := makeLevelKey("peer", nick)
	if db.Get(k) != nil {
		return errors.New("a peer with that nickname already exists")
	}

	peer := Peer{
		Nickname: nick,
		Pubkey:   pubkey,
	}

	jpeer, err := json.Marshal(&peer)
	if err != nil {
		return err
	}

	db.Set(k, jpeer)

	return nil
}

func ProposeOpeningTx(ot OpeningTx, privkey1 Privkey) []byte {
	// Write opening tx into buffer
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, ot)

	// Sign payload
	ot.Signature1 = *ed25519.Sign(privkey1, buf.Bytes()[:OpeningTxPayloadSize])

	// Clear buffer and write signed opening tx back in
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, ot)

	// Trim off empty signature to send
	return buf.Bytes()[:OpeningTxPayloadSize+SignatureSize]
}

func DeserializeOpeningTx(b []byte) (OpeningTx, error) {
	var ot OpeningTx
	err := binary.Read(b, binary.LittleEndian, ot)
	if err != nil {
		return err
	}

	if ot.Signature1 == [SignatureSize]byte{byte(0)} {
		ot.Signature1 = nil
	}

	if ot.Signature2 == [SignatureSize]byte{byte(0)} {
		ot.Signature2 = nil
	}

	if ot.Signature1 &&
		!ed25519.Verify(ot.Pubkey1, b[:OpeningTxPayloadSize], ot.Signature1) {
		return errors.New("signature 1 is invalid")
	}

	if ot.Signature2 &&
		!ed25519.Verify(ot.Pubkey2, b[:OpeningTxPayloadSize], ot.Signature2) {
		return errors.New("signature 2 is invalid")
	}

	return ot
}

func ConfirmOpeningTx(b []byte, ot OpeningTx, privkey2 Privkey) error {
	// Write opening tx into buffer
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, ot)

	// Ensure equality with the sent byte slice
	if buf.Bytes() != b {
		return errors.New("")
	}
}

// func tryingOutBinary() {
// 	pubkey1, privkey1, _ := ed25519.GenerateKey(rand.Reader)
// 	pubkey2, _, _ := ed25519.GenerateKey(rand.Reader)

// 	op := OpeningTxProposal{
// 		Pubkey1: *pubkey1,
// 		Pubkey2: *pubkey2,
// 		Amount1: 21,
// 		Amount2: 12,
// 	}

// 	buf := new(bytes.Buffer)

// 	binary.Write(buf, binary.LittleEndian, op)
// 	fmt.Println(buf)

// 	op.Signature1 = *ed25519.Sign(privkey1, buf.Bytes()[:80])

// 	buf.Reset()
// 	binary.Write(buf, binary.LittleEndian, op)
// 	fmt.Println(buf)
// }
//
