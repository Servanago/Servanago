package main

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A client on one side of the relay sees a server on the other: tools list and a call round-trips.
func TestRelayCarriesAToolCall(t *testing.T) {
	type in struct{ Name string }
	type out struct{ Greeting string }
	srv := mcp.NewServer(&mcp.Implementation{Name: "far", Version: "v1"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "greet", Description: "say hi"}, func(_ context.Context, _ *mcp.CallToolRequest, a in) (*mcp.CallToolResult, out, error) {
		return nil, out{"hi " + a.Name}, nil
	})
	farC, farS := mcp.NewInMemoryTransports()   // relay <-> far server
	nearC, nearS := mcp.NewInMemoryTransports() // test client <-> relay
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, farS) }()
	go func() { _ = relay(ctx, nearS, farC) }()

	sess, err := mcp.NewClient(&mcp.Implementation{Name: "near", Version: "v1"}, nil).Connect(ctx, nearC, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "greet", Arguments: map[string]any{"Name": "you"}})
	if err != nil || res.IsError {
		t.Fatalf("call through the relay: %v %+v", err, res)
	}
	if m, _ := res.StructuredContent.(map[string]any); m["Greeting"] != "hi you" {
		t.Errorf("result %+v", res.StructuredContent)
	}
}
