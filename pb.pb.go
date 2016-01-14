// Code generated by protoc-gen-go.
// source: pb.proto
// DO NOT EDIT!

/*
Package main is a generated protocol buffer package.

It is generated from these files:
	pb.proto

It has these top-level messages:
	OpeningTx
	UpdateTx
	Fulfillment
	Envelope
	Channel
	Identity
	Peer
*/
package main

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
const _ = proto.ProtoPackageIsVersion1

type Envelope_Type int32

const (
	Envelope_OpeningTx         Envelope_Type = 0
	Envelope_OpeningTxProposal Envelope_Type = 1
	Envelope_UpdateTx          Envelope_Type = 2
	Envelope_UpdateTxProposal  Envelope_Type = 3
	Envelope_Fulfillment       Envelope_Type = 4
)

var Envelope_Type_name = map[int32]string{
	0: "OpeningTx",
	1: "OpeningTxProposal",
	2: "UpdateTx",
	3: "UpdateTxProposal",
	4: "Fulfillment",
}
var Envelope_Type_value = map[string]int32{
	"OpeningTx":         0,
	"OpeningTxProposal": 1,
	"UpdateTx":          2,
	"UpdateTxProposal":  3,
	"Fulfillment":       4,
}

func (x Envelope_Type) String() string {
	return proto.EnumName(Envelope_Type_name, int32(x))
}
func (Envelope_Type) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{3, 0} }

type Channel_State int32

const (
	Channel_PendingOpen   Channel_State = 0
	Channel_Open          Channel_State = 1
	Channel_PendingClosed Channel_State = 2
	Channel_Closed        Channel_State = 3
)

var Channel_State_name = map[int32]string{
	0: "PendingOpen",
	1: "Open",
	2: "PendingClosed",
	3: "Closed",
}
var Channel_State_value = map[string]int32{
	"PendingOpen":   0,
	"Open":          1,
	"PendingClosed": 2,
	"Closed":        3,
}

func (x Channel_State) String() string {
	return proto.EnumName(Channel_State_name, int32(x))
}
func (Channel_State) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{4, 0} }

type OpeningTx struct {
	ChannelID  []byte `protobuf:"bytes,1,opt,name=channelID,proto3" json:"channelID,omitempty"`
	Pubkey1    []byte `protobuf:"bytes,2,opt,name=pubkey1,proto3" json:"pubkey1,omitempty"`
	Pubkey2    []byte `protobuf:"bytes,3,opt,name=pubkey2,proto3" json:"pubkey2,omitempty"`
	Amount1    uint32 `protobuf:"varint,4,opt,name=amount1" json:"amount1,omitempty"`
	Amount2    uint32 `protobuf:"varint,5,opt,name=amount2" json:"amount2,omitempty"`
	HoldPeriod uint32 `protobuf:"varint,6,opt,name=holdPeriod" json:"holdPeriod,omitempty"`
}

func (m *OpeningTx) Reset()                    { *m = OpeningTx{} }
func (m *OpeningTx) String() string            { return proto.CompactTextString(m) }
func (*OpeningTx) ProtoMessage()               {}
func (*OpeningTx) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type UpdateTx struct {
	ChannelID      []byte                `protobuf:"bytes,1,opt,name=channelID,proto3" json:"channelID,omitempty"`
	NetTransfer    int64                 `protobuf:"zigzag64,2,opt,name=netTransfer" json:"netTransfer,omitempty"`
	SequenceNumber uint32                `protobuf:"varint,3,opt,name=sequenceNumber" json:"sequenceNumber,omitempty"`
	Fast           bool                  `protobuf:"varint,4,opt,name=fast" json:"fast,omitempty"`
	Conditions     []*UpdateTx_Condition `protobuf:"bytes,5,rep,name=conditions" json:"conditions,omitempty"`
}

func (m *UpdateTx) Reset()                    { *m = UpdateTx{} }
func (m *UpdateTx) String() string            { return proto.CompactTextString(m) }
func (*UpdateTx) ProtoMessage()               {}
func (*UpdateTx) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *UpdateTx) GetConditions() []*UpdateTx_Condition {
	if m != nil {
		return m.Conditions
	}
	return nil
}

type UpdateTx_Condition struct {
	PresetCondition     uint32 `protobuf:"varint,1,opt,name=presetCondition" json:"presetCondition,omitempty"`
	ConditionalTransfer int64  `protobuf:"varint,2,opt,name=conditionalTransfer" json:"conditionalTransfer,omitempty"`
	Data                string `protobuf:"bytes,3,opt,name=data" json:"data,omitempty"`
}

func (m *UpdateTx_Condition) Reset()                    { *m = UpdateTx_Condition{} }
func (m *UpdateTx_Condition) String() string            { return proto.CompactTextString(m) }
func (*UpdateTx_Condition) ProtoMessage()               {}
func (*UpdateTx_Condition) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1, 0} }

type Fulfillment struct {
	ChannelID []byte `protobuf:"bytes,1,opt,name=channelID,proto3" json:"channelID,omitempty"`
	Condition uint32 `protobuf:"varint,2,opt,name=condition" json:"condition,omitempty"`
	Data      string `protobuf:"bytes,3,opt,name=data" json:"data,omitempty"`
}

func (m *Fulfillment) Reset()                    { *m = Fulfillment{} }
func (m *Fulfillment) String() string            { return proto.CompactTextString(m) }
func (*Fulfillment) ProtoMessage()               {}
func (*Fulfillment) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

type Envelope struct {
	Type       Envelope_Type `protobuf:"varint,1,opt,name=type,enum=main.Envelope_Type" json:"type,omitempty"`
	Payload    []byte        `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	Signature1 []byte        `protobuf:"bytes,3,opt,name=signature1,proto3" json:"signature1,omitempty"`
	Signature2 []byte        `protobuf:"bytes,4,opt,name=signature2,proto3" json:"signature2,omitempty"`
}

func (m *Envelope) Reset()                    { *m = Envelope{} }
func (m *Envelope) String() string            { return proto.CompactTextString(m) }
func (*Envelope) ProtoMessage()               {}
func (*Envelope) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

type Channel struct {
	ChannelID                []byte        `protobuf:"bytes,1,opt,name=channelID,proto3" json:"channelID,omitempty"`
	OpeningTx                *OpeningTx    `protobuf:"bytes,2,opt,name=openingTx" json:"openingTx,omitempty"`
	OpeningTxEnvelope        *Envelope     `protobuf:"bytes,3,opt,name=openingTxEnvelope" json:"openingTxEnvelope,omitempty"`
	LastUpdateTx             *UpdateTx     `protobuf:"bytes,4,opt,name=lastUpdateTx" json:"lastUpdateTx,omitempty"`
	LastUpdateTxEnvelope     *Envelope     `protobuf:"bytes,5,opt,name=lastUpdateTxEnvelope" json:"lastUpdateTxEnvelope,omitempty"`
	LastFullUpdateTx         *UpdateTx     `protobuf:"bytes,6,opt,name=lastFullUpdateTx" json:"lastFullUpdateTx,omitempty"`
	LastFullUpdateTxEnvelope *Envelope     `protobuf:"bytes,7,opt,name=lastFullUpdateTxEnvelope" json:"lastFullUpdateTxEnvelope,omitempty"`
	Me                       uint32        `protobuf:"varint,8,opt,name=me" json:"me,omitempty"`
	State                    Channel_State `protobuf:"varint,9,opt,name=state,enum=main.Channel_State" json:"state,omitempty"`
}

func (m *Channel) Reset()                    { *m = Channel{} }
func (m *Channel) String() string            { return proto.CompactTextString(m) }
func (*Channel) ProtoMessage()               {}
func (*Channel) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Channel) GetOpeningTx() *OpeningTx {
	if m != nil {
		return m.OpeningTx
	}
	return nil
}

func (m *Channel) GetOpeningTxEnvelope() *Envelope {
	if m != nil {
		return m.OpeningTxEnvelope
	}
	return nil
}

func (m *Channel) GetLastUpdateTx() *UpdateTx {
	if m != nil {
		return m.LastUpdateTx
	}
	return nil
}

func (m *Channel) GetLastUpdateTxEnvelope() *Envelope {
	if m != nil {
		return m.LastUpdateTxEnvelope
	}
	return nil
}

func (m *Channel) GetLastFullUpdateTx() *UpdateTx {
	if m != nil {
		return m.LastFullUpdateTx
	}
	return nil
}

func (m *Channel) GetLastFullUpdateTxEnvelope() *Envelope {
	if m != nil {
		return m.LastFullUpdateTxEnvelope
	}
	return nil
}

type Identity struct {
	Nickname string   `protobuf:"bytes,1,opt,name=nickname" json:"nickname,omitempty"`
	Pubkey   []byte   `protobuf:"bytes,2,opt,name=pubkey,proto3" json:"pubkey,omitempty"`
	Privkey  []byte   `protobuf:"bytes,3,opt,name=privkey,proto3" json:"privkey,omitempty"`
	Channels []string `protobuf:"bytes,4,rep,name=channels" json:"channels,omitempty"`
}

func (m *Identity) Reset()                    { *m = Identity{} }
func (m *Identity) String() string            { return proto.CompactTextString(m) }
func (*Identity) ProtoMessage()               {}
func (*Identity) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

type Peer struct {
	Nickname string   `protobuf:"bytes,1,opt,name=nickname" json:"nickname,omitempty"`
	Pubkey   []byte   `protobuf:"bytes,2,opt,name=pubkey,proto3" json:"pubkey,omitempty"`
	Channels []string `protobuf:"bytes,3,rep,name=channels" json:"channels,omitempty"`
}

func (m *Peer) Reset()                    { *m = Peer{} }
func (m *Peer) String() string            { return proto.CompactTextString(m) }
func (*Peer) ProtoMessage()               {}
func (*Peer) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func init() {
	proto.RegisterType((*OpeningTx)(nil), "main.OpeningTx")
	proto.RegisterType((*UpdateTx)(nil), "main.UpdateTx")
	proto.RegisterType((*UpdateTx_Condition)(nil), "main.UpdateTx.Condition")
	proto.RegisterType((*Fulfillment)(nil), "main.Fulfillment")
	proto.RegisterType((*Envelope)(nil), "main.Envelope")
	proto.RegisterType((*Channel)(nil), "main.Channel")
	proto.RegisterType((*Identity)(nil), "main.Identity")
	proto.RegisterType((*Peer)(nil), "main.Peer")
	proto.RegisterEnum("main.Envelope_Type", Envelope_Type_name, Envelope_Type_value)
	proto.RegisterEnum("main.Channel_State", Channel_State_name, Channel_State_value)
}

var fileDescriptor0 = []byte{
	// 664 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x9c, 0x55, 0xdd, 0x6e, 0xd3, 0x30,
	0x14, 0xa6, 0x4d, 0xda, 0x25, 0xa7, 0x6b, 0xd7, 0x9d, 0x0d, 0x14, 0x4d, 0x08, 0x4d, 0xb9, 0x80,
	0x71, 0x41, 0xc5, 0xc2, 0x0d, 0x42, 0xdc, 0xc0, 0x00, 0x69, 0x5c, 0x40, 0x65, 0x06, 0x77, 0x5c,
	0xb8, 0x8d, 0xb7, 0x45, 0x4b, 0xed, 0x90, 0xb8, 0x13, 0x15, 0x6f, 0xc1, 0x9b, 0xf0, 0x00, 0xbc,
	0x13, 0x8f, 0x80, 0xed, 0x24, 0x6e, 0xba, 0x15, 0x55, 0xe2, 0xce, 0xe7, 0x7c, 0x5f, 0xcf, 0xcf,
	0xe7, 0xcf, 0x29, 0x78, 0xd9, 0x64, 0x94, 0xe5, 0x42, 0x0a, 0x74, 0x67, 0x34, 0xe1, 0xe1, 0xaf,
	0x16, 0xf8, 0x1f, 0x33, 0xc6, 0x13, 0x7e, 0x71, 0xf6, 0x1d, 0xef, 0x83, 0x3f, 0xbd, 0xa4, 0x9c,
	0xb3, 0xf4, 0xf4, 0x4d, 0xd0, 0x3a, 0x6c, 0x1d, 0x6d, 0x93, 0x65, 0x02, 0x03, 0xd8, 0xca, 0xe6,
	0x93, 0x2b, 0xb6, 0x38, 0x0e, 0xda, 0x06, 0xab, 0xc3, 0x25, 0x12, 0x05, 0x4e, 0x13, 0x89, 0x34,
	0x42, 0x67, 0x62, 0xce, 0xe5, 0x71, 0xe0, 0x2a, 0xa4, 0x4f, 0xea, 0x70, 0x89, 0x44, 0x41, 0xa7,
	0x89, 0x44, 0xf8, 0x00, 0xe0, 0x52, 0xa4, 0xf1, 0x98, 0xe5, 0x89, 0x88, 0x83, 0xae, 0x01, 0x1b,
	0x99, 0xf0, 0x77, 0x1b, 0xbc, 0xcf, 0x59, 0x4c, 0x25, 0xdb, 0x38, 0xf2, 0x21, 0xf4, 0x38, 0x93,
	0x67, 0x39, 0xe5, 0xc5, 0x39, 0xcb, 0xcd, 0xd8, 0x48, 0x9a, 0x29, 0x7c, 0x08, 0x83, 0x82, 0x7d,
	0x9b, 0x33, 0x3e, 0x65, 0x1f, 0xe6, 0xb3, 0x89, 0x22, 0x39, 0xa6, 0xe1, 0x8d, 0x2c, 0x22, 0xb8,
	0xe7, 0xb4, 0x90, 0x66, 0x0b, 0x8f, 0x98, 0x33, 0x3e, 0x07, 0x98, 0x0a, 0x1e, 0x27, 0x32, 0x11,
	0xbc, 0x50, 0x5b, 0x38, 0x47, 0xbd, 0x28, 0x18, 0x69, 0x5d, 0x47, 0xf5, 0x7c, 0xa3, 0x93, 0x9a,
	0x40, 0x1a, 0xdc, 0x83, 0x1f, 0xe0, 0x5b, 0x00, 0x8f, 0x60, 0x27, 0xcb, 0x59, 0xc1, 0xa4, 0x4d,
	0x99, 0x45, 0xfa, 0xe4, 0x66, 0x1a, 0x9f, 0xc2, 0x9e, 0x2d, 0x42, 0xd3, 0x95, 0xb5, 0x1c, 0xb2,
	0x0e, 0xd2, 0x63, 0xab, 0x41, 0xa8, 0x59, 0xca, 0x27, 0xe6, 0x1c, 0x7e, 0x85, 0xde, 0xbb, 0x79,
	0x7a, 0x9e, 0xa4, 0xe9, 0x8c, 0x71, 0xb9, 0x41, 0x41, 0x8d, 0xda, 0xb1, 0xda, 0x66, 0xac, 0x65,
	0x62, 0x6d, 0xf9, 0x3f, 0x2d, 0xf0, 0xde, 0xf2, 0x6b, 0x96, 0x8a, 0x8c, 0xe1, 0x23, 0x70, 0xe5,
	0x22, 0x63, 0xa6, 0xee, 0x20, 0xda, 0x2b, 0xc5, 0xa9, 0xd1, 0xd1, 0x99, 0x82, 0x88, 0x21, 0x18,
	0x0b, 0xd1, 0x45, 0x2a, 0x68, 0x6c, 0xcd, 0x55, 0x86, 0xda, 0x0e, 0x45, 0x72, 0xc1, 0xa9, 0x9c,
	0xe7, 0xec, 0xb8, 0xf2, 0x57, 0x23, 0xb3, 0x82, 0x47, 0xe6, 0x7e, 0x9a, 0x78, 0x14, 0x52, 0x70,
	0x75, 0x1f, 0xec, 0x37, 0x9c, 0x3e, 0xbc, 0x83, 0x77, 0x61, 0xd7, 0x86, 0xe3, 0x5c, 0x64, 0xa2,
	0xa0, 0xe9, 0xb0, 0x85, 0xdb, 0x4b, 0x6f, 0x0d, 0xdb, 0xb8, 0x0f, 0xc3, 0x3a, 0xb2, 0x1c, 0x07,
	0x77, 0x56, 0x04, 0x1c, 0xba, 0xe1, 0x4f, 0x17, 0xb6, 0x4e, 0x4a, 0xc9, 0x36, 0xc8, 0xf9, 0x04,
	0x7c, 0x51, 0x77, 0x35, 0x8b, 0xf6, 0xa2, 0x9d, 0x52, 0x14, 0x3b, 0x0c, 0x59, 0x32, 0xf0, 0x25,
	0xec, 0xda, 0xa0, 0x56, 0xcd, 0x48, 0xd0, 0x8b, 0x06, 0xab, 0x5a, 0x92, 0xdb, 0x44, 0x8c, 0x60,
	0x3b, 0x55, 0x3e, 0xad, 0x37, 0x30, 0xda, 0xd8, 0x1f, 0xd6, 0x59, 0xb2, 0xc2, 0xc1, 0xd7, 0xb0,
	0xdf, 0x8c, 0x6d, 0xd3, 0xce, 0xda, 0xa6, 0x6b, 0xb9, 0xf8, 0x02, 0x86, 0x3a, 0xaf, 0x34, 0x4a,
	0x6d, 0xef, 0xee, 0xda, 0xde, 0xb7, 0x78, 0xf8, 0x1e, 0x82, 0x9b, 0x39, 0x3b, 0xc3, 0xd6, 0xda,
	0x19, 0xfe, 0xc9, 0xc7, 0x01, 0xb4, 0x67, 0x2c, 0xf0, 0x8c, 0x69, 0xd5, 0x09, 0x1f, 0x43, 0xa7,
	0x90, 0x8a, 0x12, 0xf8, 0x4d, 0x37, 0x56, 0x17, 0x37, 0xfa, 0xa4, 0x21, 0x52, 0x32, 0xc2, 0x57,
	0xd0, 0x31, 0xb1, 0xbe, 0xeb, 0x31, 0x53, 0x76, 0xe7, 0x17, 0xfa, 0x82, 0x94, 0x6f, 0x3c, 0x70,
	0xcd, 0xa9, 0x85, 0xbb, 0xd0, 0xaf, 0xa0, 0x93, 0x54, 0x14, 0x2c, 0x56, 0x7e, 0x01, 0xe8, 0x56,
	0x67, 0x27, 0x94, 0xe0, 0x9d, 0xc6, 0xca, 0x1f, 0x89, 0x5c, 0xe0, 0x01, 0x78, 0x3c, 0x99, 0x5e,
	0x71, 0x3a, 0x2b, 0x9f, 0x82, 0x4f, 0x6c, 0x8c, 0xf7, 0xa0, 0x5b, 0x7e, 0x2d, 0x2b, 0xe3, 0x57,
	0x91, 0x79, 0x11, 0x79, 0x72, 0xad, 0x81, 0xfa, 0xa3, 0x5a, 0x86, 0xba, 0x5a, 0xe5, 0xa8, 0x42,
	0xdd, 0xa9, 0xa3, 0xab, 0xd5, 0x71, 0xf8, 0x05, 0xdc, 0x31, 0x53, 0x0f, 0xff, 0x7f, 0x3a, 0x36,
	0xeb, 0x3a, 0xab, 0x75, 0x27, 0x5d, 0xf3, 0xaf, 0xf1, 0xec, 0x6f, 0x00, 0x00, 0x00, 0xff, 0xff,
	0xca, 0xd1, 0xe3, 0xa2, 0x41, 0x06, 0x00, 0x00,
}