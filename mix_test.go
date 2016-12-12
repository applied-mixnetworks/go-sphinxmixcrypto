// Original work Copyright 2015 2016 Lightning Onion
// Modified work Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

type HexedNodeOptions struct {
	id         string
	publicKey  string
	privateKey string
}

func newTestVectorRoute(numHops int) ([]*SphinxNode, *OnionPacket, error) {

	nodeHexOptions := []HexedNodeOptions{
		{
			id:         "ff2182654d0000000000000000000000",
			publicKey:  "d7314c8d2ba771dbe2982fa6299844f1b92736881e78ae7644f4bccbf8817a69",
			privateKey: "306e5a009897d4e134727037f9b275294bd01fb33c0c7dbe5f1fdaed765d0c47",
		},
		{
			id:         "ff0f9a62780000000000000000000000",
			publicKey:  "5ce56657b8af66bd47df2469b10065206a2fd777a0cd17b104160256810bc976",
			privateKey: "98967364dfe5d5f5d0180c727797d9111f3b1da573c25036ba16396579c25048",
		},
		{
			id:         "ffc74d10550000000000000000000000",
			publicKey:  "47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941",
			privateKey: "18c539194baae419f50ff117cbf15456a0762845af3d0a77ba85024ba488ce58",
		},
		{
			id:         "ffbb0407380000000000000000000000",
			publicKey:  "4704aff4bc2aaaa3fd187d52913a203aba4e19f6e7b491bda8c8e67daa8daa67",
			privateKey: "781e6fc7636d70dae8ebf2337538b22d7b64281a55505c1f12921e7b61f09c59",
		},
		{
			id:         "ff81855a360000000000000000000000",
			publicKey:  "73514173ee741afacdd4733e84f629b5cb9e34d28d072d749a8171fc6d64a930",
			privateKey: "9863a8f1b5307938cd4bc9782411e9eea0a38b9144d096bd923085dfb8534277",
		},
	}

	nodes := make([]*SphinxNode, NumMaxHops)
	nodeKeys := make(map[[16]byte][32]byte)
	for i := 0; i < NumMaxHops; i++ {
		params := NewParams()
		nodeID, err := hex.DecodeString(nodeHexOptions[i].id)
		if err != nil {
			return nil, nil, err
		}
		publicKey, err := hex.DecodeString(nodeHexOptions[i].publicKey)
		if err != nil {
			return nil, nil, err
		}
		privateKey, err := hex.DecodeString(nodeHexOptions[i].privateKey)
		if err != nil {
			return nil, nil, err
		}
		options := SphinxNodeOptions{}
		copy(options.id[:], nodeID)
		copy(options.publicKey[:], publicKey)
		copy(options.privateKey[:], privateKey)
		node, err := NewSphinxNode(params, &options)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create sphinx node state: %s", err)
		}
		nodes[i] = node
		nodeKeys[node.id] = node.publicKey
		//fmt.Printf("node id %x\n", node.id)
	}

	// Gather all the pub keys in the path.
	route := make([][16]byte, len(nodes))
	for i := 0; i < len(nodes); i++ {
		route[i] = nodes[i].id
	}

	// Generate a forwarding message to route to the final node via the
	// generated intermediate nodes above.
	params := NewParams()
	var destID [16]byte
	destination := route[len(route)-1]
	copy(destID[:], destination[:])
	//fmt.Printf("dest id %x %v\n\n", destID, destID)
	message := []byte("the quick brown fox")
	secret, err := hex.DecodeString("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4")
	if err != nil {
		return nil, nil, err
	}
	padding, err := hex.DecodeString("3c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		return nil, nil, err
	}
	fwdMsg, err := NewOnionPacket(params, route, nodeKeys, destID, message, secret, padding)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to create forwarding message: %#v", err)
	}

	return nodes, fwdMsg, nil
}

func newTestRoute(numHops int) ([]*SphinxNode, *OnionPacket, error) {
	nodes := make([]*SphinxNode, NumMaxHops)
	nodeKeys := make(map[[16]byte][32]byte)
	for i := 0; i < NumMaxHops; i++ {
		params := NewParams()
		node, err := NewSphinxNode(params, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create sphinx node state: %s", err)
		}
		nodes[i] = node
		nodeKeys[node.id] = node.publicKey
		//fmt.Printf("node id %x\n", node.id)
	}

	// Gather all the pub keys in the path.
	route := make([][16]byte, len(nodes))
	for i := 0; i < len(nodes); i++ {
		route[i] = nodes[i].id
	}

	// Generate a forwarding message to route to the final node via the
	// generated intermediate nodes above.
	params := NewParams()
	var destID [16]byte
	destination := []byte("dest")
	copy(destID[:], destination)
	//fmt.Printf("dest id %x %v\n\n", destID, destID)
	message := []byte("the quick brown fox")
	fwdMsg, err := NewOnionPacket(params, route, nodeKeys, destID, message, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to create forwarding message: %#v", err)
	}

	return nodes, fwdMsg, nil
}

func TestSphinxEnd2End(t *testing.T) {
	nodes, fwdMsg, err := newTestVectorRoute(NumMaxHops)
	if err != nil {
		t.Fatalf("unable to create random onion packet: %v", err)
	}

	// Now simulate the message propagating through the mix net eventually
	// reaching the final destination.
	for i := 0; i < len(nodes); i++ {
		hop := nodes[i]
		unwrappedMessage, err := hop.Unwrap(fwdMsg)
		if err != nil {
			t.Fatalf("Node %v was unabled to process the forwarding message: %v", i, err)
		}

		// If this is the last hop on the path, the node should
		// recognize that it's the exit node.
		if i == len(nodes)-1 {
			if unwrappedMessage.ProcessAction != ExitNode {
				t.Fatalf("Processing error, node %v is the last hop in "+
					"the path, yet it doesn't recognize so", i)
			}

		} else {
			// If this isn't the last node in the path, then the returned
			// action should indicate that there are more hops to go.
			if unwrappedMessage.ProcessAction != MoreHops {
				t.Fatalf("Processing error, node %v is not the final"+
					" hop, yet thinks it is.", i)
			}
			nextHop := unwrappedMessage.NextHop[:]
			if !bytes.Equal(nextHop, nodes[i+1].id[:]) {
				t.Fatalf("Processing error, next hop parsed incorrectly."+
					" next hop shoud be %v, was instead parsed as %v",
					hex.EncodeToString(nodes[i+1].id[:]),
					hex.EncodeToString(nextHop))
			}
			header := MixHeader{
				Version: byte(0),
			}
			copy(header.EphemeralKey[:], unwrappedMessage.Alpha)
			copy(header.RoutingInfo[:], unwrappedMessage.Beta)
			copy(header.HeaderMAC[:], unwrappedMessage.Gamma)
			onionPacket := OnionPacket{
				Header: &header,
			}
			copy(onionPacket.Payload[:], unwrappedMessage.Delta)
			fwdMsg = &onionPacket
		}
	}
}

func TestSphinxNodeRelpay(t *testing.T) {
	// We'd like to ensure that the sphinx node itself rejects all replayed
	// packets which share the same shared secret.
	nodes, fwdMsg, err := newTestRoute(NumMaxHops)
	if err != nil {
		t.Fatalf("unable to create test route: %v", err)
	}

	// Allow the node to process the initial packet, this should proceed
	// without any failures.
	if _, err := nodes[0].Unwrap(fwdMsg); err != nil {
		t.Fatalf("unable to process sphinx packet: %v", err)
	}

	// Now, force the node to process the packet a second time, this should
	// fail with a detected replay error.
	if _, err := nodes[0].Unwrap(fwdMsg); err != ErrReplayedPacket {
		t.Fatalf("sphinx packet replay should be rejected, instead error is %v", err)
	}
}

func TestSphinxEncodeDecode(t *testing.T) {
	// Create some test data with a randomly populated, yet valid onion
	// forwarding message.
	_, fwdMsg, err := newTestRoute(5)
	if err != nil {
		t.Fatalf("unable to create random onion packet: %v", err)
	}

	// Encode the created onion packet into an empty buffer. This should
	// succeeed without any errors.
	var b bytes.Buffer
	if err := fwdMsg.Encode(&b); err != nil {
		t.Fatalf("unable to encode message: %v", err)
	}

	// Now decode the bytes encoded above. Again, this should succeeed
	// without any errors.
	newFwdMsg := &OnionPacket{}
	if err := newFwdMsg.Decode(&b); err != nil {
		t.Fatalf("unable to decode message: %v", err)
	}

	// The two forwarding messages should now be identical.
	if !reflect.DeepEqual(fwdMsg, newFwdMsg) {
		t.Fatalf("forwarding messages don't match, %v vs %v", fwdMsg, newFwdMsg)
	}
}

func TestOnionPacketErrors(t *testing.T) {
	params := NewParams()
	route := make([][16]byte, 3)
	nodeMap := make(map[[16]byte][32]byte)
	destination := [16]byte{}
	padding := make([]byte, 1000)
	message := bytes.Repeat([]byte{3}, 1000)

	// test for payload size check error
	_, err := NewOnionPacket(params, route, nodeMap, destination, message, nil, padding)
	if err == nil {
		t.Error("expected an error")
		t.Fail()
	}

	// test AddPadding for error condition
	message = bytes.Repeat([]byte{3}, 2000)
	_, err = NewOnionPacket(params, route, nodeMap, destination, message, nil, padding)
	if err == nil {
		t.Error("expected an error")
		t.Fail()
	}

	// test handling error from NewMixHeader
	message = bytes.Repeat([]byte{3}, 500)
	padding = nil
	route = make([][16]byte, 10)
	_, err = NewOnionPacket(params, route, nodeMap, destination, message, nil, padding)
	if err == nil {
		t.Error("expected an error")
		t.Fail()
	}
}
