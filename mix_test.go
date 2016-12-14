// Original work Copyright 2015 2016 Lightning Onion
// Modified work Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"bytes"
	//"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

// FixedNoiseReader is an implementation of io.Reader
// that can be used as a replacement crypto/rand Reader
// for the purpose of writing deterministic unit tests.
type FixedNoiseReader struct {
	count int
	noise []byte
}

func NewFixedNoiseReader(noiseStr string) (*FixedNoiseReader, error) {
	noise, err := hex.DecodeString(noiseStr)
	if err != nil {
		return nil, fmt.Errorf("NewFixedNoiseReader fail: %v", err)
	}
	return &FixedNoiseReader{
		count: 0,
		noise: noise,
	}, nil
}

func (r *FixedNoiseReader) Read(data []byte) (int, error) {
	readLen := len(data)
	r.count += readLen
	if len(data) > len(r.noise) {
		return 0, fmt.Errorf("FixedNoiseReader fail: %d > %d noise", len(data), len(r.noise))
	}
	ret := r.noise[:readLen]
	r.noise = r.noise[readLen:]
	copy(data, ret)

	return readLen, nil
}

type HexedNodeOptions struct {
	id         string
	publicKey  string
	privateKey string
}

var nodeHexOptions = []HexedNodeOptions{
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

func generateRoute() (map[[16]byte][32]byte, []*SphinxNode, [][16]byte) {
	nodes := make([]*SphinxNode, NumMaxHops)
	nodeKeys := make(map[[16]byte][32]byte)
	for i := range nodeHexOptions {
		params := NewParams()
		nodeID, err := hex.DecodeString(nodeHexOptions[i].id)
		if err != nil {
			panic("wtf")
		}
		publicKey, err := hex.DecodeString(nodeHexOptions[i].publicKey)
		if err != nil {
			panic("wtf")
		}
		privateKey, err := hex.DecodeString(nodeHexOptions[i].privateKey)
		if err != nil {
			panic("wtf")
		}
		options := SphinxNodeOptions{}
		copy(options.id[:], nodeID)
		copy(options.publicKey[:], publicKey)
		copy(options.privateKey[:], privateKey)
		node, err := NewSphinxNode(params, &options)
		if err != nil {
			panic("wtf")
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
	return nodeKeys, nodes, route
}

func newTestVectorRoute(message []byte) ([]*SphinxNode, *OnionPacket, error) {
	nodeKeys, nodes, route := generateRoute()
	pki := NewDummyPKI(nodeKeys)
	params := NewParams()
	var destID [16]byte
	destination := route[len(route)-1]
	copy(destID[:], destination[:])

	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		return nil, nil, fmt.Errorf("NewFixedNoiseReader fail: %#v", err)
	}
	fwdMsg, err := NewOnionPacket(params, route, pki, destID, message, randReader)
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
	pki := NewDummyPKI(nodeKeys)
	// Gather all the pub keys in the path.
	route := make([][16]byte, len(nodes))
	for i := 0; i < len(nodes); i++ {
		route[i] = nodes[i].id
	}

	// Generate a forwarding message to route to the final node via the
	// generated intermediate nodes above.
	params := NewParams()
	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		return nil, nil, fmt.Errorf("NewFixedNoiseReader fail: %#v", err)
	}

	var destID [16]byte
	destination := []byte("dest")
	copy(destID[:], destination)
	//fmt.Printf("dest id %x %v\n\n", destID, destID)
	message := []byte("the quick brown fox")
	fwdMsg, err := NewOnionPacket(params, route, pki, destID, message, randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to create forwarding message: %#v", err)
	}

	return nodes, fwdMsg, nil
}

func TestSphinxEnd2EndVectors(t *testing.T) {
	message := []byte("the quick brown fox")
	nodes, fwdMsg, err := newTestVectorRoute(message)

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
			if !bytes.Equal(unwrappedMessage.Delta, message) {
				t.Fatal("receive incorrect message")
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

			if i == len(nodes)-2 {
				expectedGamma, err := hex.DecodeString("0b05b2c7b3cdb8e5532d409be5f32a16")
				if err != nil {
					t.Fatal("decode string fail")
				}
				if !bytes.Equal(expectedGamma, unwrappedMessage.Gamma) {
					t.Fatal("payload mismatch")
				}

				expectedBeta, err := hex.DecodeString("9f486475acc1bd3bc551700f58108ea4029a250b5e893eaaf8aeb0811d84094816b3904f69d45921448454de0eb18bfda49832492a127a5682231d3848a3cb06ca17c3427063f80d662997b30bc9307a676cd6972716d1d6ee59b657f368b0fdb0245872e5157dd3de788341518c328395b415b516bd47efb86302edf840eebd9de432e08d6b9fddd4d55f75112332e403d78e536193aa172c0dbffbc9631d8c877214abef61d54bd0a35114e5f0eace")
				if err != nil {
					t.Fatal("decode string fail")
				}
				if !bytes.Equal(expectedBeta, unwrappedMessage.Beta) {
					t.Fatal("payload mismatch")
				}

				expectedAlpha, err := hex.DecodeString("b9bc2a81df782c98a8e2b8560dc50647e2f3c013ed563b021df3e0b45378d66c")
				if err != nil {
					t.Fatal("decode string fail")
				}
				if !bytes.Equal(expectedAlpha, unwrappedMessage.Alpha) {
					t.Fatal("payload mismatch")
				}

				expectedPayload, err := hex.DecodeString("e6908ca25832a1f2f00e90f2f51ab1e407abcef6e4d3847c161e95705e7fcf8b7d9694b09989649aaf889b3c768c8ad5e8374f4410821f3e3fc3e6b838b84d14788756519b5dbcd785103c1daef9624bb3b57d763cc29f3b4aefad111129561719333d63c6b969ac3bf1d970a1b78ecc55eb5d1a2aaaf2e78bb783d756a1c3d46dc2dccfb51125b3cae26d0ef57f4b05cc92f8d2c37acc4743b4941af4e58ecd73834c0472ca3ba199b699c2c68babbd7237ee236eb6aada05c4146717bd9355d0afac129cb9246f1baeef7d7f4ec8177b8d7a32f9750c6e7f2ae1111301375cb9ccf6a218fa3970442e638febe4a7eafd73f165d53ad914aedcc5bf17e4c569d8dbe3b6827066a2193c88457e6bba94f678a64373cb1c2954dd8a80fd1c0723657779cfe0ae2238c44ae53e9b91ae70ff50d6b778a1a2c11030c41f29dfc00528784183664d8469fe0a404691bcd7cbaa1e57c8308f8fbbd76f7c0b77765a6f5f647c06527bf7b29ad58fbd2a58710503ebb6861dd449ff6df534c7622a8356d4858758de0ecb05174ce39e1c08634254b4552068d8b46f0a62e62648f12c6a32b290e295258176190c696a1f9d6c7641d3d004b47dca7914623a4855ad5fb93a144a017cdc1ad32ed1cc3dc6411f609c6f705da565f02589e9e443d8bfafa198895d71a51e45f7940938730086ffc7c480224aca67697ecce3546c4a84753a708d041ed2e5164128ffd92cdbd81e03c9af99135cbb89a96933d56d0671faebbbae21ca5e2a0154e76bd5dac36e55b983b725a878130e63313b20d9710610f3ed678d0de4442cb91e93613deaf09367f5bd1928218f0ccbc52c6046eac69039913986e60a139d063eda60975b1979a056b7bfc7635caa2ce094b77c7b36fb03f3d61183875a5dc1d4b8837a92e60669f585ca780a863ecfc0383d4361b474e3892b2361d5a7110cf1ccaf330f171dc0119861ee7c73976530f99534cdd9df0e52139de647ebbb8253c3f519e9c2acc06a671577231c7a910d09d98d79cf6db4f98e8b8b91f6e94bb0e122b002d3ea87e68f4c02ea863e45e281501d6b52bb599543d0008d5948a7e9aba0543b06e8a663cbd4e6db35e9b5d516684b57dc9f9db6a552f2e6d786c5e9d1d3c889ebe4798832e725367ad8637bd5691cf10649875b96ff488b4a22926724d0801d4df39598e4272d98ab2d2d1c7c60fc82e80974210fbc1d7f242afa57590796836e4376a17062c71b5e9ee8f40ecbba954af9129322891406b38af530e61e84966999470fa75452ebda7a79917054e6b226d7f6c85995d1485733544b2a2ebf0a2bd67445a6c061382a065ab273342975a2ac1fbb3a0f7fffd10afc18fb1bc4c315b92215160b9cdf0c09daa50d00463a6dd1fca64139df2d633b41cb2f50be46eaf821cea6b12cd361d953326386ccc87ecdb5")
				if err != nil {
					t.Fatal("decode string fail")
				}
				if !bytes.Equal(expectedPayload, unwrappedMessage.Delta) {
					t.Fatal("payload mismatch")
				}
			}
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

func TestSURB(t *testing.T) {
	nodeKeys, _, route := generateRoute()
	pki := NewDummyPKI(nodeKeys)
	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391bb1c30c0e954c5a0a70f2789f8f25584")
	if err != nil {
		t.Fatalf("NewFixedNoiseReader fail: %v", err)
	}
	client := NewSphinxClient(pki, randReader)
	_, err = client.CreateNym(route)
	if err != nil {
		t.Fatalf("failed to create SURB: %s", err)
	}
}

func BenchmarkUnwrapSphinxPacket(b *testing.B) {
	message := []byte("the quick brown fox")
	nodes, fwdMsg, err := newTestVectorRoute(message)
	if err != nil {
		b.Fatalf("unable to create random onion packet: %v", err)
	}
	for i := 0; i < b.N; i++ {
		_, err := nodes[0].Unwrap(fwdMsg)
		b.StopTimer()
		if err != nil {
			b.Fatalf("failed to process the forwarding message: %v", err)
		}
		nodes[0].seenSecrets = make(map[[32]byte]bool)
		b.StartTimer()
	}
}

func BenchmarkComposeSphinxPacket(b *testing.B) {
	nodeKeys, _, route := generateRoute()
	pki := NewDummyPKI(nodeKeys)
	var destID [16]byte
	destination := route[len(route)-1]
	copy(destID[:], destination[:])
	message := []byte("the quick brown fox")
	params := NewParams()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
		if err != nil {
			b.Fatalf("unexpected an error: %v", err)
		}
		b.StartTimer()
		_, err = NewOnionPacket(params, route, pki, destID, message, randReader)
		if err != nil {
			b.Fatalf("unexpected an error: %v", err)
		}
	}
}
