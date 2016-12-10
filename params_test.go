package sphinxmixcrypto

import (
	"crypto/rand"
	"testing"
)

func TestGroupCurve25519(t *testing.T) {
	group := NewGroupCurve25519()
	x, err := group.GenerateSecret(rand.Reader)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	blinds := [][32]byte{x}
	_ = group.MultiExpOn(group.g, blinds)
}
