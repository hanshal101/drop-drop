package main

import (
	"context"
	"fmt"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NFQueue struct {
	nf *nfqueue.Nfqueue
}

func NewNFQueue(queueNum uint16) (*NFQueue, error) {
	config := nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 65535,
		MaxQueueLen:  1024,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to create nfqueue: %w", err)
	}

	return &NFQueue{
		nf: nf,
	}, nil
}

type CallbackData struct {
	Packet   gopacket.Packet
	PacketID uint32
}

func (q *NFQueue) Register(ctx context.Context, cb func(CallbackData)) error {
	hook := func(a nfqueue.Attribute) int {
		p := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv4, gopacket.Default)
		data := CallbackData{
			Packet:   p,
			PacketID: *a.PacketID,
		}
		cb(data)
		return 0
	}

	errorFunc := func(err error) int {
		fmt.Printf("nfqueue error: %v", err)
		return 0
	}

	return q.nf.RegisterWithErrorFunc(ctx, hook, errorFunc)
}

func (q *NFQueue) SetVerdict(packetID uint32, verdict uint32) error {
	return q.nf.SetVerdict(packetID, int(verdict))
}

func (q *NFQueue) Close() {
	q.nf.Close()
}
