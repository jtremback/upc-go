package peer

import (
	"crypto/rand"
	"errors"
	"github.com/agl/ed25519"
	"github.com/golang/protobuf/proto"
	"github.com/jtremback/upc/wire"
	"io"
)

func NewChannel(ev *wire.Envelope) (Channel, error) {
	err := VerifySignatures(ev)
	if err != nil {
		return err
	}

	otx := wire.OpeningTx{}
	err := proto.Unmarshal(ev.Payload, &otx)
	if err != nil {
		return nil, err
	}

}

func VerifySignatures(ev *wire.Envelope) error {
	// Check signatures
	if !ed25519.Verify(sliceTo32Byte(ch.OpeningTx.Pubkey1), ev.Payload, sliceTo64Byte(ev.Signature1)) {
		return errors.New("signature 1 invalid")
	}
	if !ed25519.Verify(sliceTo32Byte(ch.OpeningTx.Pubkey2), ev.Payload, sliceTo64Byte(ev.Signature2)) {
		return errors.New("signature 2 invalid")
	}
}

func (ch *Channel) VerifyUpdateTx(ev *wire.Envelope) (wire.UpdateTx, error) {
	err := VerifySignatures(ev)
	if err != nil {
		return err
	}
	utx := wire.UpdateTx{}
	err := proto.Unmarshal(ev.Payload, &utx)
	if err != nil {
		return nil, err
	}

	// Check if the net transfer amount is valid
	if utx.NetTransfer > int64(ch.OpeningTx.Amount1) || utx.NetTransfer < -int64(ch.OpeningTx.Amount2) {
		return nil, errors.New("invalid amount")
	}
}

func (ch *Channel) Close(utx *wire.UpdateTx) error {
	if ch.PendingClosed != nil {
		if ch.LastFullUpdateTx.SequenceNumber > utx.SequenceNumber {
			return errors.New("update tx with higher sequence number exists")
		}
	}

	ch.State = Channel_PendingClosed
	ch.LastFullUpdateTx = utx
}
