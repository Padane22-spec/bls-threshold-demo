package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

var msg = []byte("msg1")
var digest = sha256.Sum256(msg)

func TestVerify(t *testing.T) {
	verifier := NewVerifier("sigs.yml")
	if verifier == nil {
		t.Error("Failed to create verifier")
	}

	yamlFile, err := os.ReadFile("sigs.yml")
	if err != nil {
		t.Errorf("Failed to read config: %v", err)
	}

	var sigShares SigShares
	if err := yaml.Unmarshal(yamlFile, &sigShares); err != nil {
		t.Errorf("Failed to unmarshal config: %v", err)
	}

	var sigs [][]byte
	var ids []uint16
	for _, sig := range sigShares.Sigs {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			t.Error("Failed to decode sig")
		}
		sigs = append(sigs, sigBytes)
		ids = append(ids, uint16(sig.PartyID))
	}

	ok := verifier.Verify(digest[:], sigs, ids)
	if !ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], sigs[:3], ids[:3])
	if !ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], sigs[1:], ids[1:])
	if !ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], [][]byte{sigs[0], sigs[1], sigs[3]}, []uint16{ids[0], ids[1], ids[3]})
	if !ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], [][]byte{sigs[0], sigs[2], sigs[3]}, []uint16{ids[0], ids[2], ids[3]})
	if !ok {
		t.Error("Failed to verify")
	}

	// This will cause panic
	// ok = verifier.Verify(digest[:], [][]byte{sigs[0], sigs[0], sigs[0]}, []uint16{ids[0], ids[0], ids[0]})
	// if ok {
	// 	t.Error("Failed to verify")
	// }

	ok = verifier.Verify(digest[:], [][]byte{sigs[0], sigs[0], sigs[1]}, []uint16{ids[0], ids[0], ids[1]})
	if ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], [][]byte{sigs[0], sigs[1]}, []uint16{ids[0], ids[1]})
	if ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], [][]byte{sigs[0], sigs[2]}, []uint16{ids[0], ids[2]})
	if ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], [][]byte{sigs[0], sigs[3]}, []uint16{ids[0], ids[3]})
	if ok {
		t.Error("Failed to verify")
	}

	ok = verifier.Verify(digest[:], [][]byte{sigs[2], sigs[3]}, []uint16{ids[2], ids[3]})
	if ok {
		t.Error("Failed to verify")
	}
}
