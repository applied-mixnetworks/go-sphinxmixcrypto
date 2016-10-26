package sphinxnetcrypto

import (
	"crypto/rand"
	"fmt"
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
	fmt.Printf("blinds == %d\n", blinds)
	alpha := group.MultiExpOn(group.g, blinds)
	fmt.Printf("alpha == %d\n", alpha)
}
