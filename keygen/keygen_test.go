package keygen

import (
	"bytes"
	"testing"

	bls "github.com/IBM/TSS/mpc/bls"
)

func TestSaveKeysToYAML(t *testing.T) {
	kg := testKeygen(t, 4, 3)
	err := kg.SaveKeysToYAML()
	if err != nil {
		t.Errorf("Error saving keys to YAML: %v", err)
	}
}

func TestKeygen(t *testing.T) {
	testKeygen(t, 3, 2)
	testKeygen(t, 4, 2)
	testKeygen(t, 8, 2)
	testKeygen(t, 4, 4)
	testKeygen(t, 12, 5)
	testKeygen(t, 15, 5)
	testKeygen(t, 17, 5)
}

func testKeygen(t *testing.T, n int, threshold int) *Keygen {
	kg := NewKeygen(n, threshold)
	kg.GenerateParties()
	kg.GenerateShares()
	if !isPKSame(t, kg.parties) {
		t.Errorf("Public keys are not the same")
	}
	return kg
}
func isPKSame(t *testing.T, parties []*bls.TBLS) bool {
	var lastPk []byte
	for _, p := range parties {
		pk, err := p.ThresholdPK()
		if err != nil {
			t.Errorf("Error getting threshold public key: %v", err)
			return false
		}
		if lastPk != nil {
			if !bytes.Equal(pk, lastPk) {
				t.Errorf("Public keys are not the same: %v != %v", pk, lastPk)
				return false
			}
		} else {
			lastPk = pk
		}
	}
	return true
}
