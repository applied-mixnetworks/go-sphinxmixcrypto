package sphinxmixcrypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/david415/go-lioness"
)

const (
	// The number of bytes produced by our CSPRG for the key stream
	// implementing our stream cipher to encrypt/decrypt the mix header. The
	// last 2 * securityParameter bytes are only used in order to generate/check
	// the MAC over the header.
	numStreamBytes = (2*NumMaxHops + 3) * securityParameter

	// The maximum path length.
	NumMaxHops = 10

	// Fixed size of the the routing info. This consists of a 16
	// byte address and a 16 byte HMAC for each hop of the route,
	// the first pair in cleartext and the following pairs
	// increasingly obfuscated. In case fewer than numMaxHops are
	// used, then the remainder is padded with null-bytes, also
	// obfuscated.
	routingInfoSize = pubKeyLen + (2*NumMaxHops+2)*securityParameter

	// Per-hop payload size
	HopPayloadSize = 32
	PayloadSize    = 1024
)

type MixHeader struct {
	Version      byte
	EphemeralKey [32]byte                // alpha
	RoutingInfo  [routingInfoSize]byte   // beta
	HeaderMAC    [securityParameter]byte // gamma
}

// NewMixHeader generates the a mix header containing the neccessary onion
// routing information required to propagate the message through the mixnet.
func NewMixHeader(params *Params, route [][16]byte, node_map map[[16]byte][32]byte, destination_type byte,
	destination_id [16]byte) (*MixHeader, [][32]byte, error) {

	fmt.Print("NewMixHeader")
	route_len := len(route)

	if route_len > NumMaxHops {
		return nil, nil, fmt.Errorf("route length %d exceeds max hops %d", route_len, NumMaxHops)
	}
	secret, err := params.group.GenerateSecret(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("faileed to generate curve25519 secret: %s", err)
	}

	numHops := route_len
	hopEphemeralPubKeys := make([][32]byte, numHops)
	hopSharedSecrets := make([][32]byte, numHops)
	hopBlindingFactors := make([][32]byte, numHops)
	hopBlindingFactors = append(hopBlindingFactors, secret)
	for i := 0; i < route_len; i++ {
		hopEphemeralPubKeys[i] = params.group.MultiExpOn(params.group.g, hopBlindingFactors)
		hopSharedSecrets[i] = params.group.MultiExpOn(node_map[route[i]], hopBlindingFactors)
		hopBlindingFactors[i] = params.HashBlindingFactor(hopEphemeralPubKeys[i][:], hopSharedSecrets[i])
	}

	// compute the filler strings
	hopSize := 2 * securityParameter
	filler := make([]byte, (numHops-1)*hopSize)
	for i := 1; i < numHops; i++ {
		min := (2*(NumMaxHops-i) + 3) * securityParameter
		streamBytes, err := params.GenerateCipherStream(params.GenerateStreamCipherKey(hopSharedSecrets[i-1]), numStreamBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute filler strings: %s", err)
		}
		lioness.XorBytes(filler, filler, streamBytes[min:])
	}

	// compute beta and then gamma
	slice_length := (2*(NumMaxHops-route_len)+2)*securityParameter - 1 // minus 1 for one byte destination type marker
	beta := make([]byte, slice_length)
	beta[0] = destination_type
	_, err = rand.Read(beta[1:])
	if err != nil {
		return nil, nil, fmt.Errorf("failure to read pseudo random data: %s", err)
	}
	beta_length := uint((2*(NumMaxHops-route_len) + 3) * securityParameter)
	rhoKey := params.GenerateStreamCipherKey(hopSharedSecrets[route_len-1])
	rho_cipher, err := params.GenerateCipherStream(rhoKey, beta_length)
	if err != nil {
		return nil, nil, fmt.Errorf("stream cipher fail: %s", err)
	}
	lioness.XorBytes(beta, beta, rho_cipher)
	beta = append(beta, filler...)
	gamma_key := params.GenerateHMACKey(hopSharedSecrets[route_len-1])
	gamma := params.HMAC(gamma_key, beta)
	beta = []byte{}
	for i := route_len - 2; i >= 0; i-- {
		mix_id := route[i+1]
		if len(mix_id) != securityParameter {
			return nil, nil, fmt.Errorf("invalid length mix id: %x", mix_id)
		}
		beta = append(beta, mix_id[:]...)
		beta = append(beta, gamma[:]...)

		rhoKey := params.GenerateStreamCipherKey(hopSharedSecrets[i])
		beta_length := uint((2*NumMaxHops + 1) * securityParameter)
		//beta = append(beta, beta[:(2*NumMaxHops+1)*securityParameter]...)
		rho_cipher, err := params.GenerateCipherStream(rhoKey, beta_length)
		if err != nil {
			return nil, nil, fmt.Errorf("stream cipher failure: %s", err)
		}
		lioness.XorBytes(beta, beta, rho_cipher)
		fmt.Printf("beta len %d end slice %d\n", len(beta), (2*NumMaxHops+1)*securityParameter)

		gamma = params.HMAC(params.GenerateHMACKey(hopSharedSecrets[i]), beta)
	}

	new_beta := [routingInfoSize]byte{}
	copy(new_beta[:], beta)
	new_gamma := [securityParameter]byte{}
	copy(new_gamma[:], gamma[:])
	header := &MixHeader{
		Version:      0x01,
		EphemeralKey: hopEphemeralPubKeys[0],
		RoutingInfo:  new_beta,
		HeaderMAC:    new_gamma,
	}
	return header, hopSharedSecrets, nil
}

// OnionPacket represents a forwarding message containing onion wrapped
// hop-to-hop routing information along with an onion encrypted payload message
// addressed to the final destination.
type OnionPacket struct {
	Header  *MixHeader
	Payload [PayloadSize]byte // delta
}

// NewOnionPaccket calls NewMixHeader to create the mixnet routing information
func NewOnionPacket(params *Params, route [][16]byte, node_map map[[16]byte][32]byte,
	destination [16]byte, payload []byte) (*OnionPacket, error) {

	if len(payload) > PayloadSize-4 { // XXX correcto?
		return nil, fmt.Errorf("wrong sized payload %d > %d", len(payload), PayloadSize)
	}
	paddedPayload, err := AddPadding(payload, PayloadSize)
	if err != nil {
		return nil, err
	}

	// Compute the mix header, and shared secerts for each hop.
	destination_type := byte(ExitNode)
	var destination_id [16]byte
	copy(destination_id[:], bytes.Repeat([]byte{0}, 16))
	mixHeader, hopSharedSecrets, err := NewMixHeader(params, route, node_map, destination_type, destination)
	if err != nil {
		return nil, err
	}

	// compute the delta values
	blockCipherKey, err := params.CreateBlockCipherKey(hopSharedSecrets[len(route)-1])
	if err != nil {
		return nil, err
	}
	delta, err := params.EncryptBlock(blockCipherKey, paddedPayload)
	if err != nil {
		return nil, err
	}
	for i := len(route) - 2; i > -1; i-- {
		blockCipherKey, err := params.CreateBlockCipherKey(hopSharedSecrets[len(route)-1])
		if err != nil {
			return nil, err
		}
		delta, err = params.EncryptBlock(blockCipherKey, delta)
		if err != nil {
			return nil, err
		}
	}
	newPayload := [PayloadSize]byte{}
	copy(newPayload[:], delta)
	return &OnionPacket{
		Header:  mixHeader,
		Payload: newPayload,
	}, nil
}

// Encode serializes the raw bytes of the onoin packet into the passed
// io.Writer. The form encoded within the passed io.Writer is suitable for
// either storing on disk, or sending over the network.
func (f *OnionPacket) Encode(w io.Writer) error {
	ephemeral := f.Header.EphemeralKey

	if _, err := w.Write([]byte{f.Header.Version}); err != nil {
		return err
	}

	if _, err := w.Write(ephemeral[:]); err != nil {
		return err
	}

	if _, err := w.Write(f.Header.HeaderMAC[:]); err != nil {
		return err
	}

	if _, err := w.Write(f.Header.RoutingInfo[:]); err != nil {
		return err
	}

	if _, err := w.Write(f.Payload[:]); err != nil {
		return err
	}

	return nil
}

// Decode fully populates the target ForwardingMessage from the raw bytes
// encoded within the io.Reader. In the case of any decoding errors, an error
// will be returned. If the method successs, then the new OnionPacket is
// ready to be processed by an instance of SphinxNode.
func (f *OnionPacket) Decode(r io.Reader) error {
	var err error

	f.Header = &MixHeader{}
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	f.Header.Version = buf[0]

	var ephemeral [32]byte
	if _, err := io.ReadFull(r, ephemeral[:]); err != nil {
		return err
	}
	f.Header.EphemeralKey = ephemeral
	if err != nil {
		return err
	}

	if _, err := io.ReadFull(r, f.Header.HeaderMAC[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, f.Header.RoutingInfo[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, f.Payload[:]); err != nil {
		return err
	}

	return nil
}
