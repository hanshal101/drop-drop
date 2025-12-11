package main

import (
	"context"
	"fmt"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NFQueue is a client for the nfqueue subsystem.
type NFQueue struct {
	nf *nfqueue.Nfqueue
}

// NewNFQueue creates a new NFQueue.
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

// Register registers a callback function to process packets.
func (q *NFQueue) Register(ctx context.Context, cb func(gopacket.Packet)) error {
	hook := func(a nfqueue.Attribute) int {
		p := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv4, gopacket.Default)
		cb(p)
		q.nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		return 0
	}

	errorFunc := func(err error) int {
		fmt.Printf("nfqueue error: %v", err)
		return 0
	}

	return q.nf.RegisterWithErrorFunc(ctx, hook, errorFunc)
}

// Close closes the nfqueue.
func (q *NFQueue) Close() {
	q.nf.Close()
}
