// Original work Copyright 2015 2016 Lightning Onion
// Modified work Copyright 2016 David Stainton
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE and LICENSE-lightening-onion files
// in the root of the source tree.

package sphinxmixcrypto

import (
	"io"
)

// Encode serializes the raw bytes of the onoin packet into the passed
// io.Writer. The form encoded within the passed io.Writer is suitable for
// either storing on disk, or sending over the network.
func (f *SphinxPacket) Encode(w io.Writer) error {
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
// will be returned. If the method successs, then the new SphinxPacket is
// ready to be processed by an instance of SphinxNode.
func (f *SphinxPacket) Decode(r io.Reader) error {
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
