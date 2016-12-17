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
	"errors"
	"fmt"
	"io"
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

func NewTestOnionPacketFactory(pki SphinxPKI, randReader io.Reader) *OnionPacketFactory {
	factory := OnionPacketFactory{
		group:            NewGroupCurve25519(),
		blockCipher:      NewLionessBlockCipher(),
		pki:              pki,
		randReader:       randReader,
		mixHeaderFactory: NewTestMixHeaderFactory(pki, randReader),
	}
	return &factory
}

func NewTestMixHeaderFactory(pki SphinxPKI, randReader io.Reader) *MixHeaderFactory {
	factory := MixHeaderFactory{
		group:        NewGroupCurve25519(),
		blockCipher:  NewLionessBlockCipher(),
		streamCipher: &Chacha20Stream{},
		digest:       NewBlake2bDigest(),
		pki:          pki,
		randReader:   randReader,
	}
	return &factory
}

type ExpectedState struct {
	hop                       string
	alpha, beta, gamma, delta string
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
		node := NewSphinxNode(&options)
		nodes[i] = node
		nodeKeys[node.id] = node.publicKey
	}
	// Gather all the pub keys in the path.
	route := make([][16]byte, len(nodes))
	for i := 0; i < len(nodes); i++ {
		route[i] = nodes[i].id
	}
	return nodeKeys, nodes, route
}

func newTestRoute(numHops int) ([]*SphinxNode, *OnionPacket, error) {
	nodes := make([]*SphinxNode, NumMaxHops)
	nodeKeys := make(map[[16]byte][32]byte)
	for i := 0; i < NumMaxHops; i++ {
		options, err := NewSphinxNodeOptions()
		if err != nil {
			return nil, nil, err
		}
		node := NewSphinxNode(options)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create sphinx node state: %s", err)
		}
		nodes[i] = node
		nodeKeys[node.id] = node.publicKey
	}
	pki := NewDummyPKI(nodeKeys)
	// Gather all the pub keys in the path.
	route := make([][16]byte, len(nodes))
	for i := 0; i < len(nodes); i++ {
		route[i] = nodes[i].id
	}

	// Generate a forwarding message to route to the final node via the
	// generated intermediate nodes above.
	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		return nil, nil, fmt.Errorf("NewFixedNoiseReader fail: %#v", err)
	}

	var destID [16]byte
	destination := []byte("dest")
	copy(destID[:], destination)
	message := []byte("the quick brown fox")
	onionPacketFactory := NewTestOnionPacketFactory(pki, randReader)
	fwdMsg, err := onionPacketFactory.BuildForwardOnionPacket(route, destID, message)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to create forwarding message: %#v", err)
	}

	return nodes, fwdMsg, nil
}

func TestSphinxNodeReplay(t *testing.T) {
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

func MixStateMachine(firstHop [16]byte, nodeMap map[[16]byte]*SphinxNode, onionPacket *OnionPacket, expected ExpectedState) (*UnwrappedMessage, error) {
	var err error
	unwrappedMessage := &UnwrappedMessage{}
	var hop [16]byte
	var decodedHop []byte
	copy(hop[:], firstHop[:])

	for {
		node, ok := nodeMap[hop]
		if !ok {
			return nil, fmt.Errorf("failed to find node id %x in nodeMap", hop)
		}
		unwrappedMessage, err = node.Unwrap(onionPacket)
		if err != nil {
			return nil, fmt.Errorf("Node %x was unabled to process the message: %v", firstHop, err)
		}

		if unwrappedMessage.ProcessAction == MoreHops {
			header := MixHeader{
				Version: byte(0),
			}
			copy(header.EphemeralKey[:], unwrappedMessage.Alpha)
			copy(header.RoutingInfo[:], unwrappedMessage.Beta)
			copy(header.HeaderMAC[:], unwrappedMessage.Gamma)
			onionPacket = &OnionPacket{
				Header: &header,
			}
			copy(onionPacket.Payload[:], unwrappedMessage.Delta)
			copy(hop[:], unwrappedMessage.NextHop)

			decodedHop, err = hex.DecodeString(expected.hop)
			if err != nil {
				unwrappedMessage = nil
				err = errors.New("hex decode fail")
				break
			}
			if bytes.Equal(decodedHop[:], hop[:]) {
				err = EqualHexBytes(expected.alpha, unwrappedMessage.Alpha)
				if err != nil {
					unwrappedMessage = nil
					err = errors.New("alpha mismatch")
					break
				}
				err = EqualHexBytes(expected.beta, unwrappedMessage.Beta)
				if err != nil {
					unwrappedMessage = nil
					err = errors.New("beta mismatch")
					break
				}
				err = EqualHexBytes(expected.gamma, unwrappedMessage.Gamma)
				if err != nil {
					unwrappedMessage = nil
					err = errors.New("gamma mismatch")
					break
				}
				err = EqualHexBytes(expected.delta, unwrappedMessage.Delta)
				if err != nil {
					unwrappedMessage = nil
					err = errors.New("delta mismatch")
					break
				}
			}
		} else if unwrappedMessage.ProcessAction == ClientHop {
			break
		} else if unwrappedMessage.ProcessAction == ExitNode {
			break
		} else {
			unwrappedMessage = nil
			err = fmt.Errorf("onion packet unwrap failure: invalid process action")
			break
		}
	}
	return unwrappedMessage, err
}

func EqualHexBytes(h string, b []byte) error {
	decoded, err := hex.DecodeString(h)
	if err != nil {
		return errors.New("hex decode fail")
	}
	if bytes.Equal(decoded, b) {
		return nil
	}
	return errors.New("not equal")
}

func NewTestSphinxClient(pki SphinxPKI, randReader io.Reader, id []byte) *SphinxClient {
	var newID [4]byte
	if id == nil {
		_, err := randReader.Read(newID[:])
		if err != nil {
		}
		id = []byte(fmt.Sprintf("Client %x", newID))
	}
	return &SphinxClient{
		id:               id,
		keysmap:          make(map[[16]byte][][]byte),
		pki:              pki,
		randReader:       randReader,
		blockCipher:      NewLionessBlockCipher(),
		mixHeaderFactory: NewTestMixHeaderFactory(pki, randReader),
	}
}

func TestSURB(t *testing.T) {
	nodeKeys, nodes, route := generateRoute()
	nodeMap := make(map[[16]byte]*SphinxNode)
	for i := range nodes {
		nodeMap[nodes[i].id] = nodes[i]
	}
	pki := NewDummyPKI(nodeKeys)
	randReader, err := NewFixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb8")
	if err != nil {
		t.Fatalf("NewFixedNoiseReader fail: %v", err)
	}
	client := NewTestSphinxClient(pki, randReader, nil)
	surb, err := client.CreateNym(route)
	if err != nil {
		t.Fatalf("failed to create SURB: %v", err)
	}
	message := []byte("Open, secure and reliable connectivity is necessary (although not sufficient) to excercise the human rights such as freedom of expression and freedom of association [FOC], as defined in the Universal Declaration of Human Rights [UDHR].")
	firstHop, onionPacket, err := client.WrapReply(surb, message)
	if err != nil {
		t.Fatalf("failed to wrap reply: %v", err)
	}

	var hop [16]byte
	copy(hop[:], firstHop)
	expect := ExpectedState{
		hop:   "ff81855a360000000000000000000000",
		alpha: "cbe28bea4d68103461bc0cc2db4b6c4f38bc82af83f5f1de998c33d46c15f72d",
		beta:  "a5578dc72fcea3501169472b0877ca46627789750820b29a3298151e12e04781645f6007b6e773e4b7177a67adf30d0ec02c472ddf7609eba1a1130c80789832fb201eed849c02244465f39a70d7520d641be371020083946832d2f7da386d93b4627b0121502e5812209d674b3a108016618b2e9f210978f46faaa2a7e97a4d678a106631581cc51120946f5915ee2bfd9db11e5ec93ae7ffe4d4dc8ab66985cfe9da441b708e4e5dc7c00ea42abf1a",
		gamma: "49533c3dda5a7cc2fa611e3616a70ce4",
		delta: "461422572d19853267d1a145be5c028e4f45d43f2997b2281fadd895c904f1ba58b843af676f54c14a6129297968ab367381495b2308d454200897fa00e6cc89b4c28a5939a6978e82cfe22c45a441a25a8602fcb95bc10434c9f7f187b919fe6e09af4e5493b92781ce28ba30427e5d29923267c3fd3dd7ee2a0bd11f4b5871f4f95583c09fd971df0bebc9a2e28302d56e366a8d32133c1d8cf1b3a3066d38a5534c23f7713d96a0090c492ecf9b6e79a60e26fd49516e07f3c5d8abc13bee8ba2cd5f5b19ff81279b25329f125b6c0a5784a72cbab9557d1013bc77887a7a03b9b71fbf9124e177a2042c64d4772199b91ccfc1f6daa7fd5a2507b4159697bc0a6eee78452ebe5201125001e7a1c5c1b59dd2e2a1fa8ada1b1d1bd8a441ee03fb93e9831f457bf04841cd77f370878e569f8c3170e859682bbeaadcc7a7436a1b10718ccec1e606578343df76e22615ea9f9c591bee570e3ffdf883c03384854149ae701f8cdd00142d11b2fdf18616e517b812bb609fcf17d9d751fe0d55e17a409570c8840e1397110f1a74f6d3c7185e9af2918a47d09bc0ba38836946987c2f6357c0225fa86f0659a5ccddb6336d86395a23a3b732c62a61abe51a6b2dc41c2988172cc5eb872a2fb5bfa2235c55d3a088cbf94aca21378e961ee1034f9fdf08ae8b524c4c3d6f965a328810634ee90a967813970700de7c2f40a52f7cd107f0faf3cecaa7f02409447a8585f81c64429b470aaa302226e660c77541a017f8c9fe1856e537024866274bb3921ce048407425bbd819f8ba0e43f9e27c98a3006db703328bcae4ca5899279a87b37bcd8a0a3391d02af7cf0781a4f12d8ef6db354f9541389a9ee8e3df2a6cc86ec2aeaad9468f461ff52ecfae4a8abb967d6c8cdb4af602c974fc68d5dd0039c5b0b6103b0d81ee4fe2076526ae4ba87a8fb7d9533372c6b7442872f93fdbeaf352270433ddef101f81f94791782573605773375b17f10f4352af3c6b068c5e7b7954e47449401424047b898851bb8073425e5cb28b818a7701afa58ae5e9ea8961555a63ecb4af8b0fcb3f9689934b964e3b570c543cd715d330205248ada019b5d437b84ae891a4291d7e12a63c61f93e408c933c3a6773b925adf31e3694c82afc966f78444d9d572ac454de3aa70fe7a7a0b2f6d1e2cd29123f0a51e0acd88bb37c55b0d113e1b701df362125c7d820eb8d9fc641663dc35c221e12a5949ffdd72777b992d23961f92fb06996dd4d64817674ced5b8d7f1e15c7bd1e7ea8cdc6e846e4003afe92d9c6b1b249735fa8d796e584c37f035e6024a618b970064d59ab8d9612df260439292e848b95722589e3441b42fef2866eeb40bff03104c49d7113bd556ebd4eb6531f6ef2d76db150f09466d810948f206f861d7ff128ed508a045e4c3e097424fe07d7803b4",
	}
	unwrappedMessage, err := MixStateMachine(hop, nodeMap, onionPacket, expect)
	if err != nil {
		t.Fatalf("MixStateMachine failed: %v", err)
	}
	var messageID [16]byte
	copy(messageID[:], unwrappedMessage.MessageID)
	payload, err := client.Decrypt(messageID, unwrappedMessage.Delta)
	if err != nil {
		t.Fatalf("client decrypt failure: %v", err)
	}
	if !bytes.Equal(message, payload[:]) {
		t.Fatal("client decrypted message mismatch")
	}
}

func TestVectorsSendMessage(t *testing.T) {
	message := []byte("the quick brown fox")
	nodeKeys, nodes, route := generateRoute()
	nodeMap := make(map[[16]byte]*SphinxNode)
	for i := range nodes {
		nodeMap[nodes[i].id] = nodes[i]
	}
	pki := NewDummyPKI(nodeKeys)
	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		t.Fatalf("NewFixedNoiseReader fail: %#v", err)
	}

	onionPacketFactory := NewTestOnionPacketFactory(pki, randReader)
	onionPacket, err := onionPacketFactory.BuildForwardOnionPacket(route, route[len(route)-1], message)
	if err != nil {
		t.Fatalf("Unable to create forwarding message: %#v", err)
	}
	var firstHop [16]byte
	copy(firstHop[:], route[0][:])
	expect := ExpectedState{
		hop:   "ff81855a360000000000000000000000",
		alpha: "b9bc2a81df782c98a8e2b8560dc50647e2f3c013ed563b021df3e0b45378d66c",
		beta:  "9f486475acc1bd3bc551700f58108ea4029a250b5e893eaaf8aeb0811d84094816b3904f69d45921448454de0eb18bfda49832492a127a5682231d3848a3cb06ca17c3427063f80d662997b30bc9307a676cd6972716d1d6ee59b657f368b0fdb0245872e5157dd3de788341518c328395b415b516bd47efb86302edf840eebd9de432e08d6b9fddd4d55f75112332e403d78e536193aa172c0dbffbc9631d8c877214abef61d54bd0a35114e5f0eace",
		gamma: "0b05b2c7b3cdb8e5532d409be5f32a16",
		delta: "e6908ca25832a1f2f00e90f2f51ab1e407abcef6e4d3847c161e95705e7fcf8b7d9694b09989649aaf889b3c768c8ad5e8374f4410821f3e3fc3e6b838b84d14788756519b5dbcd785103c1daef9624bb3b57d763cc29f3b4aefad111129561719333d63c6b969ac3bf1d970a1b78ecc55eb5d1a2aaaf2e78bb783d756a1c3d46dc2dccfb51125b3cae26d0ef57f4b05cc92f8d2c37acc4743b4941af4e58ecd73834c0472ca3ba199b699c2c68babbd7237ee236eb6aada05c4146717bd9355d0afac129cb9246f1baeef7d7f4ec8177b8d7a32f9750c6e7f2ae1111301375cb9ccf6a218fa3970442e638febe4a7eafd73f165d53ad914aedcc5bf17e4c569d8dbe3b6827066a2193c88457e6bba94f678a64373cb1c2954dd8a80fd1c0723657779cfe0ae2238c44ae53e9b91ae70ff50d6b778a1a2c11030c41f29dfc00528784183664d8469fe0a404691bcd7cbaa1e57c8308f8fbbd76f7c0b77765a6f5f647c06527bf7b29ad58fbd2a58710503ebb6861dd449ff6df534c7622a8356d4858758de0ecb05174ce39e1c08634254b4552068d8b46f0a62e62648f12c6a32b290e295258176190c696a1f9d6c7641d3d004b47dca7914623a4855ad5fb93a144a017cdc1ad32ed1cc3dc6411f609c6f705da565f02589e9e443d8bfafa198895d71a51e45f7940938730086ffc7c480224aca67697ecce3546c4a84753a708d041ed2e5164128ffd92cdbd81e03c9af99135cbb89a96933d56d0671faebbbae21ca5e2a0154e76bd5dac36e55b983b725a878130e63313b20d9710610f3ed678d0de4442cb91e93613deaf09367f5bd1928218f0ccbc52c6046eac69039913986e60a139d063eda60975b1979a056b7bfc7635caa2ce094b77c7b36fb03f3d61183875a5dc1d4b8837a92e60669f585ca780a863ecfc0383d4361b474e3892b2361d5a7110cf1ccaf330f171dc0119861ee7c73976530f99534cdd9df0e52139de647ebbb8253c3f519e9c2acc06a671577231c7a910d09d98d79cf6db4f98e8b8b91f6e94bb0e122b002d3ea87e68f4c02ea863e45e281501d6b52bb599543d0008d5948a7e9aba0543b06e8a663cbd4e6db35e9b5d516684b57dc9f9db6a552f2e6d786c5e9d1d3c889ebe4798832e725367ad8637bd5691cf10649875b96ff488b4a22926724d0801d4df39598e4272d98ab2d2d1c7c60fc82e80974210fbc1d7f242afa57590796836e4376a17062c71b5e9ee8f40ecbba954af9129322891406b38af530e61e84966999470fa75452ebda7a79917054e6b226d7f6c85995d1485733544b2a2ebf0a2bd67445a6c061382a065ab273342975a2ac1fbb3a0f7fffd10afc18fb1bc4c315b92215160b9cdf0c09daa50d00463a6dd1fca64139df2d633b41cb2f50be46eaf821cea6b12cd361d953326386ccc87ecdb5",
	}
	unwrappedMessage, err := MixStateMachine(firstHop, nodeMap, onionPacket, expect)
	if err != nil {
		t.Fatalf("mix state fail: %v", err)
	}
	if !bytes.Equal(unwrappedMessage.Delta, message) {
		t.Fatal("receive message does not match")
	}
}

func BenchmarkUnwrapSphinxPacket(b *testing.B) {
	message := []byte("the quick brown fox")
	//nodes, fwdMsg, err := newTestVectorRoute(message)
	nodeKeys, nodes, route := generateRoute()
	nodeMap := make(map[[16]byte]*SphinxNode)
	for i := range nodes {
		nodeMap[nodes[i].id] = nodes[i]
	}
	pki := NewDummyPKI(nodeKeys)
	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		b.Fatalf("NewFixedNoiseReader fail: %#v", err)
	}
	onionPacketFactory := NewTestOnionPacketFactory(pki, randReader)
	fwdMsg, err := onionPacketFactory.BuildForwardOnionPacket(route, route[len(route)-1], message)
	if err != nil {
		b.Fatalf("Unable to create forwarding message: %#v", err)
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

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
		if err != nil {
			b.Fatalf("unexpected an error: %v", err)
		}
		b.StartTimer()
		onionPacketFactory := NewTestOnionPacketFactory(pki, randReader)
		_, err = onionPacketFactory.BuildForwardOnionPacket(route, destID, message)
		if err != nil {
			b.Fatalf("unexpected an error: %v", err)
		}
	}
}
