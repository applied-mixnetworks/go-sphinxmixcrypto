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

	"git.schwanenlied.me/yawning/chacha20"
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
	_, ok := v.seenSecrets[tag]
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

// DummyPKI implements the SphinxPKI interface
// however this is only really useful for testing
// mixnet functionality on a single machine.
type DummyPKI struct {
	nodeKeyStateMap map[[16]byte]*SimpleKeyState
}

// NewDummyPKI creates a new DummyPKI
func NewDummyPKI(nodeKeyStateMap map[[16]byte]*SimpleKeyState) *DummyPKI {
	return &DummyPKI{
		nodeKeyStateMap: nodeKeyStateMap,
	}
}

// Get returns the public key for a given identity.
// PKIKeyNotFound is returned upon failure.
func (p *DummyPKI) Get(id [16]byte) ([32]byte, error) {
	nilKey := [32]byte{}
	_, ok := p.nodeKeyStateMap[id]
	if ok {
		return p.nodeKeyStateMap[id].publicKey, nil
	}
	return nilKey, ErrorPKIKeyNotFound
}

// Identities returns all the identities the PKI knows about.
func (p *DummyPKI) Identities() [][16]byte {
	var identities [][16]byte
	for id := range p.nodeKeyStateMap {
		identities = append(identities, id)
	}
	return identities
}

type ChachaEntropyReader struct {
	cipher *chacha20.Cipher
}

func NewChachaEntropyReader(keyStr string) (*ChachaEntropyReader, error) {
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}
	var nonce [8]byte
	cipher, err := chacha20.NewCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}
	reader := ChachaEntropyReader{
		cipher: cipher,
	}
	return &reader, err
}

func (r *ChachaEntropyReader) Read(data []byte) (int, error) {
	readLen := len(data)
	buf := make([]byte, readLen)
	r.cipher.XORKeyStream(data, buf)
	return readLen, nil
}

func TestChachaEntropyReader(t *testing.T) {
	randReader, err := NewChachaEntropyReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
	if err != nil {
		t.Fatalf("fail: %#v", err)
	}
	fu := [32]byte{}
	randReader.Read(fu[:])
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

var testRoute = []string{"ff2182654d0000000000000000000000", "ff0f9a62780000000000000000000000", "ffc74d10550000000000000000000000", "ffbb0407380000000000000000000000", "ff81855a360000000000000000000000"}

func getTestRoute() [][16]byte {
	route := [][16]byte{}
	for i := range testRoute {
		nodeId, err := hex.DecodeString(testRoute[i])
		if err != nil {
			panic("wtf")
		}
		nodeIdArr := [16]byte{}
		copy(nodeIdArr[:], nodeId)
		route = append(route, nodeIdArr)
	}
	return route
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

func generateNodeKeyStateMap() map[[16]byte]*SimpleKeyState {
	nodeKeyStateMap := make(map[[16]byte]*SimpleKeyState)
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
		keyState := SimpleKeyState{}
		copy(keyState.id[:], nodeID)
		copy(keyState.publicKey[:], publicKey)
		copy(keyState.privateKey[:], privateKey)
		nodeKeyStateMap[keyState.id] = &keyState
	}
	return nodeKeyStateMap
}

func TestSphinxNodeReplay(t *testing.T) {
	keyStateMap := generateNodeKeyStateMap()
	route := getTestRoute()
	replayCache := NewSimpleReplayCache()
	keyState := SimpleKeyState{}
	nodeID, err := hex.DecodeString(nodeHexOptions[0].id)
	if err != nil {
		panic("wtf")
	}
	publicKey, err := hex.DecodeString(nodeHexOptions[0].publicKey)
	if err != nil {
		panic("wtf")
	}
	privateKey, err := hex.DecodeString(nodeHexOptions[0].privateKey)
	if err != nil {
		panic("wtf")
	}
	copy(keyState.id[:], nodeID)
	copy(keyState.publicKey[:], publicKey)
	copy(keyState.privateKey[:], privateKey)
	pki := NewDummyPKI(keyStateMap)
	// this fake entropy source makes this test deterministic
	randReader, err := NewChachaEntropyReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
	if err != nil {
		t.Fatalf("fail: %#v", err)
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
	if _, err := SphinxPacketUnwrap(&params, replayCache, &keyState, fwdMsg); err != nil {
		t.Fatalf("unable to process sphinx packet: %v", err)
	}

	// Now, force the node to process the packet a second time, this should
	// fail with a detected replay error.
	if _, err := SphinxPacketUnwrap(&params, replayCache, &keyState, fwdMsg); err != ErrReplayedPacket {
		t.Fatalf("sphinx packet replay should be rejected, instead error is %v", err)
	}
}

// MixStateMachine is used for testing
func MixStateMachine(firstHop [16]byte, replayCacheMap map[[16]byte]*SimpleReplayCache, keyStateMap map[[16]byte]*SimpleKeyState, sphinxPacket *SphinxPacket, expected ExpectedState) (*UnwrappedMessage, error) {
	var err error
	unwrappedMessage := &UnwrappedMessage{}
	var hop [16]byte
	var decodedHop []byte
	copy(hop[:], firstHop[:])
	betaLen := uint(176) // XXX fix me
	params := SphinxParams{
		PayloadSize: 1024,
		MaxHops:     5,
	}

	for {
		replayCache, ok := replayCacheMap[hop]
		if !ok {
			return nil, fmt.Errorf("failed to find node id %x in nodeMap", hop)
		}
		keyState, ok := keyStateMap[hop]
		if !ok {
			return nil, fmt.Errorf("failed to find node id %x in nodeMap", hop)
		}
		unwrappedMessage, err = SphinxPacketUnwrap(&params, replayCache, keyState, sphinxPacket)
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
				// fmt.Printf("ALPHA %x\n", unwrappedMessage.Alpha)
				// fmt.Printf("BETA %x\n", unwrappedMessage.Beta)
				// fmt.Printf("GAMMA %x\n", unwrappedMessage.Gamma)
				// fmt.Printf("DELTA %x\n", unwrappedMessage.Delta)
				err = EqualHexBytes(expected.alpha, unwrappedMessage.Alpha)
				if err != nil {
					err = errors.New("alpha mismatch")
					unwrappedMessage = nil
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
	keyStateMap := generateNodeKeyStateMap()
	replayCacheMap := make(map[[16]byte]*SimpleReplayCache)
	route := getTestRoute()
	for nodeId, _ := range keyStateMap {
		replayCache := NewSimpleReplayCache()
		replayCacheMap[nodeId] = replayCache
	}
	pki := NewDummyPKI(keyStateMap)
	// this fake entropy source makes this test deterministic
	randReader, err := NewChachaEntropyReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
	if err != nil {
		t.Fatalf("fail: %v", err)
	}
	params := SphinxParams{
		MaxHops:     5,
		PayloadSize: 1024,
	}
	clientId, err := hex.DecodeString("0f436c69656e74206665656463383061")
	if err != nil {
		t.Fatalf("fail: %v", err)
	}
	messageId, err := hex.DecodeString("ff81855a360000000000000000000000")
	messageIdAr := [16]byte{}
	copy(messageIdAr[:], messageId)
	destination := [16]byte{}
	copy(destination[:], clientId)
	decryptionToken, replyBlock, err := ComposeReplyBlock(messageIdAr, &params, route, pki, destination, randReader)
	if err != nil {
		panic(err)
	}
	message := []byte("Open, secure and reliable connectivity is necessary (although not sufficient) to excercise the human rights such as freedom of expression and freedom of association [FOC], as defined in the Universal Declaration of Human Rights [UDHR].")
	firstHop, sphinxPacket, err := replyBlock.ComposeForwardMessage(&params, message)
	if err != nil {
		panic(err)
	}
	var hop [16]byte
	copy(hop[:], firstHop)
	expected := ExpectedState{
		hop:   "ff81855a360000000000000000000000",
		alpha: "b00eb0894f1b49530150c33cc4055cf3b97f3cac22f03f25050394bf5d80c954",
		beta:  "1c162721f4896fa5054be6dec39a00dc8efdf23c574de810ed5e5dca8b0d0ef0b410306377c251f3cb855f466b3f7b696dda60a914e03d6e537fe3e712cbb98e414e0cfec3fd14f0e79b66fc0338820aabb680cc6cb9274b836852bd737ecc121e828697675fc839ebf820ba9d53e17f94b5bad2631f915ae059d4e37fa04b776158f306d92ce2bce232f60412feff11c754450970bba6a318e45f9ce9210202d669c7bf7c38eb1c14b9cda4e6311eba",
		gamma: "eff2a11d309fa2c07832c1ecb0917078",
		delta: "aac22e90370689f1ef5ded95cc593b4c7fd5b796df440ebfe5ae1a90921312d89bbf76eda53b23a18c6dab15966fd4a4806099b28d6b06723087586e5c56aded125f6c067edccb8322a1696a892498d8d6cfdca2a758d0687b5c6a8a8207e04c0810e2c95da8db03fd5e4f91326b23cd9ccebd403bab33d59184aff393cc26779fbb56d80c10ff10507a9fc24cc61d00f27d27f076439f3c06f97ffbc97a02918aba1d2aceac013ec22d528148295f5e501559d9ed4d9f8064aca4c0ab3542678b24144f1814869d34a536ae2b4f2c6f330cd9f579f048dc592059b126feae908815f1fc4557aabfb559aa218b37b83270e5da67fc0eab152b1971701906ebaf6b7a9510cb766c975ca984098063f079f2fbb7108a59feb87983a15e9cb50cc8b3c8b7c6bdfe435b7feade94be9193df304b4eb09ec7490774b6cbfd7d86663ba59685d3beadcb82cab429bcb7244a5d06e58b3172b858bc87a3b6db5260a5a2cc476dd9b959416e286e8e3579460c9257bcdf3564319d92bd66d1bafe47ddea32f202cdb1f0bf64ef23abb37b251026437a1dc6e260dbf63d387067b35a27ea70fd6cde2a2f6037b58f433bc22f18d944c90e05ab9d8b22ef06ad8ce3ac98afb39f0ec823f64ee8b620ab332b65b275f2b11ddd722ba51771286add25193b8dbbee47bf188f78aea393337a50c2353910a849abe81a30d77ffdb3483480ff81af8d5d298c912606c1a92eac84e37c9ac24885b8e8bfd39fdfe68dbb2e3bf2bbd87bdb8c7fcda8d4cbb80706530d13aff83d53e3fd5aa02a7544c910c8b4a73366bd388bb3459d3501195b6a7a4dd03703948ae78811bf4996f0be68c8c6340c6a4df620f8c4a9dce6bd20d1fd6e1ce15bc885821bc35c0ffbf367e05b48329bb40d81461360c4921441cfff72a0cc4e6697ad709a05b503ab29364d01daa74a26e1fb548a8d5aebba97696c2fee10ca9f871f954f647c0233d50ec0fb48b5cc47a5c2b4493250ad35029f0e1da8f0a9088178d1ef8264e6d24d8d1580afb1bf816c0bb65c6022ef718775ca207c358cb15e50805b297c6a5d129cfc8e609dca434fb07f09ed199d8f9e7254622ee3e136c43b4e36f287ed857f526f08a3835ac5e8c9f1242e08cb7db38747c5c129a468b2d4035c12ee66ed75f72dda853bbf5ac2920dc6726c72f8e3be2058ad985ac8c2e0263b3ebece2857a2eb0d4f76b3330ac378ceaff1b809226d9de4088943d4a8e834dc3f9ef5dbdfc55991e6fa4cf9c6f5e44119fea12ecbb2d699302f53d4809c87e0fd9c331b283a29fbaffaf66af1c931f16c32c3ae2f4459240ceb6170760f785a1156d6bf568a69c594857abd8a826d5fa38d5d59e1bd034736a97bd221304950687186474bc9aab6b8315647c84b0925a026c03dc795f015a6ce345d7f76a02a11ff28518ddcaf99547ab7",
	}
	unwrappedMessage, err := MixStateMachine(hop, replayCacheMap, keyStateMap, sphinxPacket, expected)
	if err != nil {
		t.Fatalf("MixStateMachine failed: %v", err)
	}
	var messageID [16]byte
	copy(messageID[:], unwrappedMessage.MessageID)
	plaintext, err := decryptionToken.Decrypt(unwrappedMessage.Delta)
	if err != nil {
		t.Fatalf("client decrypt failure: %v", err)
	}
	if !bytes.Equal(message, plaintext[:]) {
		t.Fatal("client decrypted message mismatch")
	}
}

func TestVectorsSendMessage(t *testing.T) {
	message := []byte("the quick brown fox")
	keyStateMap := generateNodeKeyStateMap()
	replayCacheMap := make(map[[16]byte]*SimpleReplayCache)
	route := getTestRoute()
	for nodeId, _ := range keyStateMap {
		replayCacheMap[nodeId] = NewSimpleReplayCache()
	}
	pki := NewDummyPKI(keyStateMap)
	// this fake entropy source makes this test deterministic
	randReader, err := NewChachaEntropyReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
	if err != nil {
		t.Fatalf("fail: %#v", err)
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
	expected := ExpectedState{
		hop:   "ff81855a360000000000000000000000",
		alpha: "b00eb0894f1b49530150c33cc4055cf3b97f3cac22f03f25050394bf5d80c954",
		beta:  "13554b4891e71b85632e83baa0a230bd710b818a9d94863c7732deb742c167b3570b6799f99ff76c94bc58b613ff073e6dda60a914e03d6e537fe3e712cbb98e414e0cfec3fd14f0e79b66fc0338820aabb680cc6cb9274b836852bd737ecc121e828697675fc839ebf820ba9d53e17f94b5bad2631f915ae059d4e37fa04b776158f306d92ce2bce232f60412feff11c754450970bba6a318e45f9ce9210202d669c7bf7c38eb1c14b9cda4e6311eba",
		gamma: "0b747d558acd9d59ceedc1f876634644",
		delta: "0269f1c546605e56162c97ed66054a14565e868193f159b1f25f962bb29a94581826586f955fff0841a9266bc6cb75aa8f217c6d2998bdbdf3782e0e0e8eaa2d3e159ccecccb12c7476d015de13daa6e4d757cf979abadba7e8a92153e5f28f56c94f084d3a9da487ff4a1f478b470f89c74e18179e7aff47e82710f973952a66043d341e27d54370506d63344a6fc738d39d1af3cc1d8394aeaf46a286688c9882fc95077a6b0b438cda481400e56debd0468aa9d5656a7e920ce0882bd07bee35801389ceb9a377a399e639a1d257d7ecd047c161f273faf1026ce5c3f7e5855865be24f53bb48e34dea1bad0c688c4c07564d8d771a8ad8ce980520d81da565a7da0e9e70eb1e975621729f146f090d8ad5e475ed42b4d68993c8ff7a75aaab4ef29d620b4caf5761a41887f3952950bc974468ef4381ebd8dc36dee74f9e1603c195527d84f45bcb18f9161ce5ba989abbc8fe887bbf90c6e2aa453f728bfdef11b776fff9796d8e3affe7b945a38f50285eb9e3dd3697082f0bbd554ea9f5c31e57c1e7f252fe76b69d7af55c9668688d1114de093c6c837dcd8a2836d3ed5199171860288806111893a468666e9ac83562d02d660f183451dbfdd094d26a988ae4bf67a86ae56fbef6a1a8cf53fa304ec41ac93a80c5b68a29e2fa195fa4b165659bf4dc6e2cff12becb34e5c7c6fa567868483f1ced888a441412408f51cff75c3e31d2535d95f9029017d02d993f6bd4b14b9f9d819a207afa7b38a4f70af0c93a3234c96a612f2633e456f2d09bd334fa8015a39f762c301e9fdcf4c525f2549e228dd10ea8549620606ac893a2a299644678ebb8872a217374289a4f75c638268929064f1f5ff51b4aa142fac7fe63d6b155fcc8539c34405635b9da0b7602dba8b6df82335ef03cc9afcc818761f1f4c87ac9e6a39caa249a99131492a8e48de7af9caf3aea7448936d6d2ce9b24f8a53385377196d16e69de43cb84ce6435a68d4e10fbcefeefeca20023ae76d34c7405f16d33d726073052985189cd4ec92d7a4d8cedf29e10a56c27fd5aa2be904d823a4b345bb2f4ae2e7c8ccc95a2e144fa012ad44bf7ee811f51965d90b60c590ab6794868e1d76b7678202a37473e6bd945ced2bd7802b7a5117cb87af00a43d5edae7830bdeb72440d071ce24fe59c4610fc7119044bd3f5d60aeabcc394f020e8e300ad0fe9b58023ca6470345514dab5a7212ce17b612094fadfc7f6e3d5542bff77f80e785064307d5ec8c26b80f06fb3b7d4d6f4c42b647564f4ba05371ef8c02f1fd32a2ae7522425136ab6eb8206f2e0094d78b644b7057aad1d2afa5f9e6abf082da932076cf63b173a1eef549ba18522200748705bac31e950849826a153185f9180aa71553fdb25152ac2a1674c8b007ba78274af411363b6dab068c3d0ceaec2873d96ba7",
	}
	unwrappedMessage, err := MixStateMachine(firstHop, replayCacheMap, keyStateMap, sphinxPacket, expected)

	if err != nil {
		t.Fatalf("mix state fail: %v", err)
	}
	if !bytes.Equal(unwrappedMessage.Delta, message) {
		t.Fatal("receive message does not match")
	}
}

func BenchmarkUnwrapSphinxPacket(b *testing.B) {
	message := []byte("the quick brown fox")
	route := getTestRoute()
	replayCache := NewSimpleReplayCache()
	keyStateMap := generateNodeKeyStateMap()
	keyState := SimpleKeyState{}
	nodeID, err := hex.DecodeString(nodeHexOptions[0].id)
	if err != nil {
		panic("wtf")
	}
	publicKey, err := hex.DecodeString(nodeHexOptions[0].publicKey)
	if err != nil {
		panic("wtf")
	}
	privateKey, err := hex.DecodeString(nodeHexOptions[0].privateKey)
	if err != nil {
		panic("wtf")
	}
	copy(keyState.id[:], nodeID)
	copy(keyState.publicKey[:], publicKey)
	copy(keyState.privateKey[:], privateKey)
	pki := NewDummyPKI(keyStateMap)
	// this fake entropy source makes this test deterministic
	randReader, err := NewChachaEntropyReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
	if err != nil {
		b.Fatalf("fail: %#v", err)
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
		_, err := SphinxPacketUnwrap(&params, replayCache, &keyState, fwdMsg)
		b.StopTimer()
		if err != nil {
			b.Fatalf("failed to process the forwarding message: %v", err)
		}
		replayCache.Flush()
		b.StartTimer()
	}
}

func BenchmarkComposeSphinxPacket(b *testing.B) {
	keyStateMap := generateNodeKeyStateMap()
	route := getTestRoute()
	pki := NewDummyPKI(keyStateMap)
	var destID [16]byte
	destination := route[len(route)-1]
	copy(destID[:], destination[:])
	message := []byte("the quick brown fox")

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// this fake entropy source makes this test deterministic
		randReader, err := NewChachaEntropyReader("47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941")
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
