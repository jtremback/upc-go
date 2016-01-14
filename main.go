package main

import (
	// "bytes"
	"crypto/rand"
	// "strings"
	// "encoding/binary"
	// "encoding/json"
	"errors"
	"io"
	// "fmt"
	"github.com/agl/ed25519"
	"github.com/golang/protobuf/proto"
	// "github.com/jtremback/upc/memdb"
	// "log"
)

func calcConditionalTransfer(lst *UpdateTx) int64 {
	// Sum up all conditional transfer amounts and add to net transfer
	var ct int64
	for _, v := range lst.Conditions {
		ct += v.ConditionalTransfer
	}

	return ct
}

// NewUpdateTxProposal makes a new UpdateTx with NetTransfer changed to add amt
func NewUpdateTxProposal(amount uint32, ch *Channel) (*UpdateTx, error) {
	lst := ch.LastUpdateTx
	nt := lst.NetTransfer

	// Check if we are pubkey1 or pubkey2 and add or subtract amount from net transfer
	switch ch.Me {
	case 1:
		nt += int64(amount)
	case 2:
		nt -= int64(amount)
	}

	// Add conditional transfer
	nt += calcConditionalTransfer(lst)

	// Check if the net transfer amount is still valid
	if nt > int64(ch.OpeningTx.Amount1) || nt < -int64(ch.OpeningTx.Amount2) {
		return nil, errors.New("invalid amount")
	}

	// Make new update transaction
	return &UpdateTx{
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

func SignUpdateTxProposal(utx *UpdateTx, ident *Identity, ch *Channel) (*Envelope, error) {
	// Serialize update transaction
	data, err := proto.Marshal(utx)
	if err != nil {
		return nil, err
	}

	// Sign update transaction, convert signature to slice
	sig := ed25519.Sign(sliceTo64Byte(ident.Privkey), data)

	// Make new envelope
	ev := Envelope{
		Type:    Envelope_UpdateTxProposal,
		Payload: data,
	}

	// Put signature in correct slot
	switch ch.Me {
	case 1:
		ev.Signature1 = sig[:]
	case 2:
		ev.Signature2 = sig[:]
	}

	return &ev, nil
}

func VerifyUpdateTxProposal(ev *Envelope, ch *Channel) (uint32, error) {
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

	utx := UpdateTx{}
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

func randomBytes(c uint) ([]byte, error) {
	b := make([]byte, c)
	n, err := io.ReadFull(rand.Reader, b)
	if n != len(b) || err != nil {
		return nil, err
	}
	return b, nil
}

func NewChannel(ident Identity, peer Peer, myAmount uint32, theirAmount uint32, holdPeriod uint32) (*Channel, error) {
	chID, err := randomBytes(32)
	if err != nil {
		return nil, err
	}

	ch := &Channel{
		ChannelID: chID,
		OpeningTx: &OpeningTx{
			ChannelID:  chID,
			Pubkey1:    ident.Pubkey,
			Pubkey2:    peer.Pubkey,
			Amount1:    myAmount,
			Amount2:    theirAmount,
			HoldPeriod: holdPeriod,
		},
		Me:    1,
		State: Channel_PendingOpen,
	}

	// Serialize update transaction
	data, err := proto.Marshal(ch.OpeningTx)
	if err != nil {
		return nil, err
	}

	// Make new envelope
	ch.OpeningTxEnvelope = &Envelope{
		Type:       Envelope_UpdateTxProposal,
		Payload:    data,
		Signature1: ed25519.Sign(sliceTo64Byte(ident.Privkey), data)[:],
	}

	return ch, nil
}

func (ch *Channel) Close() (*Envelope, error) {
	ev := ch.LastFullUpdateTxEnvelope

	// Sign update transaction, convert signature to slice
	sig := ed25519.Sign(sliceTo64Byte(ident.Privkey), ev.Payload)

	// Put signature in correct slot
	switch ch.Me {
	case 1:
		ev.Signature1 = sig[:]
	case 2:
		ev.Signature2 = sig[:]
	}

	// Change channel state to pending closed
	ch.State = Channel_PendingClosed

	return ev, nil
}

func (ch *Channel) ConfirmClose(utx *UpdateTx) {
	ch.LastUpdateTx = utx
	ch.LastFullUpdateTx = utx
	// Change channel state to closed
	ch.State = Channel_Closed
}

// func CoopClose(ch *Channel) (*Envelope, error) {

// }

// func makeLevelKey(indexes ...string) []byte {
// 	return []byte(strings.Join(indexes, ":"))
// }

// func MakeKeypair() (*[PublicKeySize]byte, *[PrivateKeySize]byte, error) {
// 	return ed25519.GenerateKey(rand.Reader)
// }
