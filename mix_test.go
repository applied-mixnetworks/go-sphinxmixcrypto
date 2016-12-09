package sphinxmixcrypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

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
	// generated intermdiates nodes above.
	params := NewParams()
	var destination_id [16]byte
	copy(destination_id[:], bytes.Repeat([]byte{0}, 16)) // XXX
	message := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 9}
	fwdMsg, err := NewOnionPacket(params, route, nodeKeys, destination_id, message)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to create forwarding message: %#v", err)
	}

	return nodes, fwdMsg, nil
}

func TestSphinxCorrectness(t *testing.T) {
	nodes, fwdMsg, err := newTestRoute(NumMaxHops)
	if err != nil {
		t.Fatalf("unable to create random onion packet: %v", err)
	}

	// Now simulate the message propagating through the mix net eventually
	// reaching the final destination.
	for i := 0; i < len(nodes); i++ {
		hop := nodes[i]
		fmt.Printf("<><><><><><<<< Processing at hop: %v \n\n", i)

		unwrappedMessage, err := hop.Unwrap(fwdMsg)
		if err != nil {
			t.Fatalf("Node %v was unabled to process the forwarding message: %v", i, err)
		}

		fmt.Println("finished unwrapping message")

		// If this is the last hop on the path, the node should
		// recognize that it's the exit node.
		if i == len(nodes)-1 {
			if unwrappedMessage.ProcessAction != ExitNode {
				t.Fatalf("Processing error, node %v is the last hop in "+
					"the path, yet it doesn't recognize so", i)
			}

		} else {
			fmt.Println("process ACTION", unwrappedMessage.ProcessAction)

			// If this isn't the last node in the path, then the returned
			// action should indicate that there are more hops to go.
			if unwrappedMessage.ProcessAction != MoreHops {
				t.Fatalf("Processing error, node %v is not the final"+
					" hop, yet thinks it is.", i)
			}

			parsedNextHop := unwrappedMessage.NextHop[:]
			if !bytes.Equal(parsedNextHop, nodes[i+1].id[:]) {
				t.Fatalf("Processing error, next hop parsed incorrectly."+
					" next hop shoud be %v, was instead parsed as %v",
					hex.EncodeToString(nodes[i+1].id[:]),
					hex.EncodeToString(parsedNextHop))
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
