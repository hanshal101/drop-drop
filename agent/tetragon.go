package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TetragonClient is a client for the Tetragon gRPC API.
type TetragonClient struct {
	conn   *grpc.ClientConn
	client tetragon.FineGuidanceSensorsClient
}

// NewTetragonClient creates a new TetragonClient.
func NewTetragonClient(address string) (*TetragonClient, error) {
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to tetragon: %w", err)
	}

	client := tetragon.NewFineGuidanceSensorsClient(conn)

	return &TetragonClient{
		conn:   conn,
		client: client,
	}, nil
}

// Close closes the connection to the Tetragon gRPC server.
func (c *TetragonClient) Close() {
	c.conn.Close()
}

// GetEvents streams events from the Tetragon gRPC server.
func (c *TetragonClient) GetEvents(ctx context.Context, events chan<- *tetragon.GetEventsResponse) {
	req := &tetragon.GetEventsRequest{}

	stream, err := c.client.GetEvents(ctx, req)
	if err != nil {
		log.Printf("could not get events: %v", err)
		return
	}

	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("error while receiving events: %v", err)
			return
		}
		events <- res
	}
}
