package main

import (
	"fmt"
	"github.com/agl/ed25519"
	"github.com/jtremback/upc/pb"
	"reflect"
	"testing"
)

var ident = &pb.Identity{
	Nickname: "alfred",
	Pubkey:   []byte{71, 153, 85, 86, 207, 54, 51, 205, 34, 228, 234, 81, 223, 175, 82, 180, 154, 154, 29, 46, 181, 45, 223, 143, 205, 48, 159, 75, 237, 51, 200, 0},
	Privkey:  []byte{147, 131, 100, 59, 112, 77, 196, 211, 124, 170, 199, 79, 190, 194, 175, 244, 1, 9, 48, 255, 200, 168, 138, 165, 187, 46, 251, 28, 183, 13, 214, 5, 71, 153, 85, 86, 207, 54, 51, 205, 34, 228, 234, 81, 223, 175, 82, 180, 154, 154, 29, 46, 181, 45, 223, 143, 205, 48, 159, 75, 237, 51, 200, 0},
	Channels: []string{"shibby"},
}

var ch = &pb.Channel{
	ChannelID: "shibby",
	OpeningTx: &pb.OpeningTx{
		Amount1: 100,
		Amount2: 100,
	},
	LastUpdateTx: &pb.UpdateTx{
		ChannelID:      "shibby",
		NetTransfer:    -24,
		SequenceNumber: 1,
	},
	Me: 1,
}

func TestMakeUpdateTxProposal(t *testing.T) {
	ideal := &pb.UpdateTx{
		ChannelID:      "shibby",
		NetTransfer:    -12,
		SequenceNumber: 2,
		Fast:           false,
	}
	actual, err := MakeUpdateTxProposal(12, ch)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(ideal, actual) {
		t.Error("incorrect output")
	}
}

func TestSignUpdateTxProposal(t *testing.T) {
	utx, err := MakeUpdateTxProposal(12, ch)
	if err != nil {
		t.Error(err)
	}

	ev, err := SignUpdateTxProposal(utx, ident, ch)
	if err != nil {
		t.Error(err)
	}

	if !ed25519.Verify(sliceTo32Byte(ident.Pubkey), ev.Payload, sliceTo64Byte(ev.Signature1)) {
		t.Error("invalid signature")
	}

	fmt.Println(ev)
}
