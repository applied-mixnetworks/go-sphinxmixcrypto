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
	"testing"
)

type SimpleReplayCache struct {
	seenSecrets map[[32]byte]bool
}

func NewSimpleReplayCache() *SimpleReplayCache {
	state := SimpleReplayCache{
		seenSecrets: make(map[[32]byte]bool),
	}
	return &state
}

func (v *SimpleReplayCache) Get(tag [32]byte) bool {
	_, ok := n.seenSecrets[tag]
	return ok
}

func (v *SimpleReplayCache) Set(tag [32]byte) {
	v.seenSecrets[tag] = true
}

func (v *SimpleReplayCache) Flush() {
	v.seenSecrets = make(map[[32]byte]bool)
}

type SimpleKeyState struct {
	privateKey [32]byte
	publicKey  [32]byte
	id         [16]byte
}

func (v *SimpleKeyState) GetPrivateKey() [32]byte {
	return v.privateKey
}

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
	nodes := make([]*SphinxNode, 5) // 5 is max hops
	nodeKeys := make(map[[16]byte][32]byte)
	params := SphinxParams{
		PayloadSize: 1024,
		MaxHops:     5,
	}
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
		node := NewSphinxNode(&options, &params)
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

func TestSphinxNodeReplay(t *testing.T) {
	nodeKeys, nodes, route := generateRoute()
	nodeMap := make(map[[16]byte]*SphinxNode)
	for i := range nodes {
		nodeMap[nodes[i].id] = nodes[i]
	}
	pki := NewDummyPKI(nodeKeys)
	// this fake entropy source makes this test deterministic
	randReader, err := NewFixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb8")
	if err != nil {
		t.Fatalf("NewFixedNoiseReader fail: %#v", err)
	}
	params := SphinxParams{
		MaxHops:     5,
		PayloadSize: 1024,
	}
	packetFactory := NewSphinxPacketFactory(&params, pki, randReader)
	message := []byte("the quick brown fox")
	fwdMsg, err := packetFactory.BuildForwardSphinxPacket(route, route[len(route)-1], message)
	if err != nil {
		t.Fatalf("Unable to create forwarding message: %#v", err)
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

func MixStateMachine(firstHop [16]byte, nodeMap map[[16]byte]*SphinxNode, sphinxPacket *SphinxPacket, expected ExpectedState) (*UnwrappedMessage, error) {
	var err error
	unwrappedMessage := &UnwrappedMessage{}
	var hop [16]byte
	var decodedHop []byte
	copy(hop[:], firstHop[:])

	betaLen := uint(176) // XXX fix me
	for {
		node, ok := nodeMap[hop]
		if !ok {
			return nil, fmt.Errorf("failed to find node id %x in nodeMap", hop)
		}
		unwrappedMessage, err = node.Unwrap(sphinxPacket)
		if err != nil {
			return nil, fmt.Errorf("Node %x was unabled to process the message: %v", firstHop, err)
		}

		if unwrappedMessage.ProcessAction == MoreHops {
			header := MixHeader{
				Version: byte(0),
			}

			header.RoutingInfo = make([]byte, betaLen)
			copy(header.EphemeralKey[:], unwrappedMessage.Alpha)
			copy(header.RoutingInfo, unwrappedMessage.Beta)
			copy(header.HeaderMAC[:], unwrappedMessage.Gamma)
			sphinxPacket = &SphinxPacket{
				Header: &header,
			}
			sphinxPacket.Payload = make([]byte, len(unwrappedMessage.Delta))
			copy(sphinxPacket.Payload[:], unwrappedMessage.Delta)
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

func TestSURB(t *testing.T) {
	nodeKeys, nodes, route := generateRoute()
	nodeMap := make(map[[16]byte]*SphinxNode)
	for i := range nodes {
		nodeMap[nodes[i].id] = nodes[i]
	}
	pki := NewDummyPKI(nodeKeys)
	// this fake entropy source makes this test deterministic
	randReader, err := NewFixedNoiseReader("b5451d2eb2faf3f84bc4778ace6516e73e9da6c597e6f96f7e63c7ca6c9456018be9fd84883e4469a736c66fcaeceacf080fb06bc45859796707548c356c462594d1418b5349daf8fffe21a67affec10c0a2e3639c5bd9e8a9ddde5caf2e1db802995f54beae23305f2241c6517d301808c0946d5895bfd0d4b53d8ab2760e4ec8d4b2309eec239eedbab2c6ae532da37f3b633e256c6b551ed76321cc1f301d74a0a8a0673ea7e489e984543ca05fe0ff373a6f3ed4eeeaafd18292e3b182c25216aeb8")
	if err != nil {
		t.Fatalf("NewFixedNoiseReader fail: %v", err)
	}
	params := SphinxParams{
		MaxHops:     5,
		PayloadSize: 1024,
	}
	client, err := NewSphinxClient(&params, pki, nil, randReader)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	surb, err := client.CreateNym(route)
	if err != nil {
		t.Fatalf("failed to create SURB: %v", err)
	}
	message := []byte("Open, secure and reliable connectivity is necessary (although not sufficient) to excercise the human rights such as freedom of expression and freedom of association [FOC], as defined in the Universal Declaration of Human Rights [UDHR].")
	firstHop, sphinxPacket, err := client.WrapReply(surb, message)
	if err != nil {
		t.Fatalf("failed to wrap reply: %v", err)
	}

	var hop [16]byte
	copy(hop[:], firstHop)
	expect := ExpectedState{
		hop:   "ff81855a360000000000000000000000",
		alpha: "cbe28bea4d68103461bc0cc2db4b6c4f38bc82af83f5f1de998c33d46c15f72d",
		beta:  "a5578dc72fcea3501169472b0877ca46627789750820b29a3298151e12e04781645f6007b6e773e4b7177a67adf30d0ec02c472ddf7609eba1a1130c80789832fb201eed849c02244465f39a70d7520d641be371020083946832d2f7da386d93b4627b0121502e5812209d674b3a108016618b2e9f210978f46faaa2a7e97a4d678a106631581cc51120946f5915ee2bfd9db11e5ec93ae7ffe4d4dc8ab66985cfe9da441b708e4e5dc7c00ea42abf1a",
		gamma: "976fdfd8262dbb7557c988588ac9a204",
		delta: "0a9411a57044d20b6c4004c730a78d79550dc2f22ba1c9c05e1d15e0fcadb6b1b353f028109fd193cb7c14af3251e6940572c7cd4243977896504ce0b59b17e8da04de5eb046a92f1877b55d43def3cc11a69a11050a8abdceb45bc1f09a22960fdffce720e5ed5767fbb62be1fd369dcdea861fd8582d01666a08bf3c8fb691ac5d2afca82f4759029f8425374ae4a4c91d44d05cb1a64193319d9413de7d2cfdffe253888535a8493ab8a0949a870ae512d2137630e2e4b2d772f6ee9d3b9d8cadd2f6dc34922701b21fa69f1be6d0367a26c2875cb7afffe60d59597cc084854beebd80d559cf14fcb6642c4ab9102b2da409685f5ca9a23b6c718362ccd6405d993dbd9471b4e7564631ce714d9c022852113268481930658e5cee6d2538feb9521164b2b1d4d68c76967e2a8e362ef8f497d521ee0d57bcd7c8fcc4c673f8f8d700c9c71f70c73194f2eddf03f954066372918693f8e12fc980e1b8ad765c8806c0ba144b86277170b12df16b47de5a2596b2149c4408afbe8f790d3cebf1715d1c4a9ed5157b130a66a73001f6f344c74438965e85d3cac84932082e6b17140f6eb901e3de7b3a16a76bdde2972c557d573830e8a455973de43201b562f63f5b3dca8555b5215fa138e81da900358ddb4d123b57b4a4cac0bfebc6ae3c7d54820ca1f3ee9908f7cb81200afeb1fdafdfbbc08b15d8271fd18cfd7344b36bdd16cca082235c3790888dae22e547bf436982c1a1935e2627f1bb16a3b4942f474d2ec1ff15eb6c3c4e320892ca1615ecd462007e51fbc69817719e6d641c101aa153bff207974bbb4f9553a8d6fb0cfa2cb1a497f9eee32f7c084e97256c72f06f020f33a0c079f3f69c2ce0e2826cc396587d80c9485e26f70633b70ad2e2d531a44407d101628c0bdae0cd47d6032e97b73e1231c3db06a2ead13eb20878fc198a345dd9dafc54b0cc56bcf9aa64e85002ff91a3f01dc97de5e85d68707a4909385cefbd6263cf9624a64d9052291da48d33ac401854cce4d6a7d21be4b5f1f4616e1784226603fdadd45d802ab226c81ec1fc1827310c2c99ce1c7ee28f38fbc7cf637132a1a2b1e5835762b41f0c7180a7738bac5cedebc11cdbf229e2155a085349b93cb94ce4285ea739673cc719e46cacb56663564057df1a0a2f688ed216336ff695337d6922f0185c23c3c04294388da192d9ae2b51ff18a8cc4d3212e1b2b19fed7b8f3662c2f9bd463f75e1e7c738db6b204f8f5aa8176e238d41c8d828b124e78c294be2d5b2bf0724958b787b0bea98d9a1534fc9975d66ee119b47b2e3017c9bba9431118c3611840b0ddcb00450024d484080d29c3896d92913eaca52d67f313a482fcc6ab616673926bdbdb1a2e62bcb055755ae5b3a975996e40736fde300717431c7d7b182369f90a092aef94e58e0ea5a4b15e76d",
	}
	unwrappedMessage, err := MixStateMachine(hop, nodeMap, sphinxPacket, expect)
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
	// this fake entropy source makes this test deterministic
	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		t.Fatalf("NewFixedNoiseReader fail: %#v", err)
	}
	params := SphinxParams{
		MaxHops:     5,
		PayloadSize: 1024,
	}
	sphinxPacketFactory := NewSphinxPacketFactory(&params, pki, randReader)
	sphinxPacket, err := sphinxPacketFactory.BuildForwardSphinxPacket(route, route[len(route)-1], message)
	if err != nil {
		t.Fatalf("Unable to create forwarding message: %#v", err)
	}
	var firstHop [16]byte
	copy(firstHop[:], route[0][:])
	expect := ExpectedState{
		hop:   "ff81855a360000000000000000000000",
		alpha: "b9bc2a81df782c98a8e2b8560dc50647e2f3c013ed563b021df3e0b45378d66c",
		beta:  "9f486475acc1bd3bc551700f58108ea4029a250b5e893eaaf8aeb0811d84094816b3904f69d45921448454de0eb18bfda49832492a127a5682231d3848a3cb06ca17c3427063f80d662997b30bc9307a676cd6972716d1d6ee59b657f368b0fdb0245872e5157dd3de788341518c328395b415b516bd47efb86302edf840eebd9de432e08d6b9fddd4d55f75112332e403d78e536193aa172c0dbffbc9631d8c877214abef61d54bd0a35114e5f0eace",
		gamma: "59f86271afb940c9e7c187b9966b9a42",
		delta: "320e9422cb6ecdc8de8cebacf32dd676d9e8142070856275ff39efacc39d09ff61f75f2633c232015f638d4ac72ee211b41d1f3351f600b47c1638640956fff1f00f61a744a4df75ed730de2eb3b5bb4fa65df8d775d606705ccf0ce8f66a444f04dfaee50c0d23c4ae1b217bf28e49db77df4b91aba049514ed1c8f55648f176b4a9d3045433d838063a830523e6e5bdc53e0278734436df2a3936df05b2ae68fadf26e7913216606ec1dbcd64cf54e0f63bd03e08bcd7d73eb6336d70104b1f85c0d8086a4da656d1bdc24b91cc443efa9022223af8d651d04b5611931cd7d91fe4a5ef031e0409ff80fc398e350fe9307d9b3c673b60c162c5581630ae7733f947a214979f7e7ef8e8481a1e59eec700d92e6d8ca279a06d4ff3c6f960c74b6473842c44323576b383de01a4b16077fe740d6f3dfabad6fc85d3b972dccca9eb9040f9b2df3b21e7e679df41d6a5750df3c9da5a9ca2a5d9a7b233378a195e7ec995fc588fef6f537ec082d7b755dffee56646bc75f7f38bdb91945e3aa6aeee0fe5cd31eed271e69b930a9893e3dc0ca8516afa382eb72fab61e915b8b70babef87a69460fec2e26a3c34983271766746f034c4562d62d494e70b444b6ff7d71f866133858fece4baaa18442a7528a0cba298169c3c315b00369569a23040d26db6df452a7d79f7ed2e7aebcdee23f34765f0f91917a00353c4692f64c20f4517cd7826f1962dd3fcda86a4ba0772fb5d9466ab340359233bf6452f4b5cd208f5a40114a1ceed1fb643a4e7bb676bcb16bd8eb78b0082a3a1dcc17f84f984c820885ac90cc9f249fec002d929747875f4fb31752d5d586addb512e122256e4c1350e7df34a2c1d708f4a4f51ce5527e2b9757a4cf199be26d53124fe0ac965694723224b9fbccf78ad3c2d873d480569b853ffdb526b9a5b9f17d26f27cad103237e19e69c24cc8d27637f1cbef38aa93eb5d221878d806373579e1760facd50690926260a3ae0a544f5788ef11d03266295d6794b1ba3d5861aa715b1e989f09fe3ed645ba6a5ccb9b4474d874189f149d9617bc0cf3f071aaa04d3f2d7a5d8b143b234f266dfcbd892ba502215785c39abf98b5617c4b2a4c9284d562f8c26da44200fbd526a4469677cb925a6a26322ac2e651df6f32b3fe0fc393a6eab18a48b7d2c54346ae5cc0ffcb539adf0ce398d180f78577427749a8c99edf55f91677fcc451762978b384966baeb63b20d4ad7e5ec2f9bc63812ffb8a14074cbca66bd80b3df6cb50024f332f4c466efb5bed156845d3deb6785df4d1dc99021ce70a1cd575b7e65739ee7e02baf955605ee3cc9e335e811bd28eda3482fa8cd25e50e56950828bc0bfe3d0489b0149242c4e5d39d7d4f8f1b049c530e8e827359573bcc18abcc30ee639341375b56cb6ffc5702e0912955059ee974bc603f",
	}
	unwrappedMessage, err := MixStateMachine(firstHop, nodeMap, sphinxPacket, expect)
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
	// this fake entropy source makes this test deterministic
	randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
	if err != nil {
		b.Fatalf("NewFixedNoiseReader fail: %#v", err)
	}
	params := SphinxParams{
		MaxHops:     5,
		PayloadSize: 1024,
	}
	sphinxPacketFactory := NewSphinxPacketFactory(&params, pki, randReader)
	fwdMsg, err := sphinxPacketFactory.BuildForwardSphinxPacket(route, route[len(route)-1], message)
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
		// this fake entropy source makes this test deterministic
		randReader, err := NewFixedNoiseReader("82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b43c78e065c89b26bc7b498dd6c0f24925c67a7ac0d4a191937bc7698f650391")
		if err != nil {
			b.Fatalf("unexpected an error: %v", err)
		}
		b.StartTimer()
		params := SphinxParams{
			MaxHops:     5,
			PayloadSize: 1024,
		}
		sphinxPacketFactory := NewSphinxPacketFactory(&params, pki, randReader)
		_, err = sphinxPacketFactory.BuildForwardSphinxPacket(route, destID, message)
		if err != nil {
			b.Fatalf("unexpected an error: %v", err)
		}
	}
}
