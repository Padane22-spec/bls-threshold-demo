package sign

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var msg = []byte("msg1")
var digest = sha256.Sum256(msg)

func TestNewSigner(t *testing.T) {
	signer0 := NewSigner("./config_0.yml")
	if signer0 == nil {
		t.Error("Failed to create signer")
	}
	signer1 := NewSigner("./config_1.yml")
	if signer1 == nil {
		t.Error("Failed to create signer")
	}
	signer2 := NewSigner("./config_2.yml")
	if signer2 == nil {
		t.Error("Failed to create signer")
	}
	signer3 := NewSigner("./config_3.yml")
	if signer3 == nil {
		t.Error("Failed to create signer")
	}
}

func TestSign(t *testing.T) {
	signer0 := NewSigner("./config_0.yml")
	if signer0 == nil {
		t.Error("Failed to create signer")
	}
	signer1 := NewSigner("./config_1.yml")
	if signer1 == nil {
		t.Error("Failed to create signer")
	}
	signer2 := NewSigner("./config_2.yml")
	if signer2 == nil {
		t.Error("Failed to create signer")
	}
	signer3 := NewSigner("./config_3.yml")
	if signer3 == nil {
		t.Error("Failed to create signer")
	}

	sig0, err := signer0.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}
	sig1, err := signer1.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}
	sig2, err := signer2.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}
	sig3, err := signer3.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}

	if len(sig0) != 64 {
		t.Error("Failed to sign")
	}
	if len(sig1) != 64 {
		t.Error("Failed to sign")
	}
	if len(sig2) != 64 {
		t.Error("Failed to sign")
	}
	if len(sig3) != 64 {
		t.Error("Failed to sign")
	}
}

func TestSigSave(t *testing.T) {
	signer0 := NewSigner("./config_0.yml")
	if signer0 == nil {
		t.Error("Failed to create signer")
	}
	signer1 := NewSigner("./config_1.yml")
	if signer1 == nil {
		t.Error("Failed to create signer")
	}
	signer2 := NewSigner("./config_2.yml")
	if signer2 == nil {
		t.Error("Failed to create signer")
	}
	signer3 := NewSigner("./config_3.yml")
	if signer3 == nil {
		t.Error("Failed to create signer")
	}

	sig0, err := signer0.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}
	sig1, err := signer1.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}
	sig2, err := signer2.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}
	sig3, err := signer3.Sign(digest[:])
	if err != nil {
		t.Error("Failed to sign")
	}

	sigShares := SigShares{
		TotalParties: 3,
		Threshold:    2,
		Sigs: []SigShare{
			{PartyID: 0, Sig: base64.StdEncoding.EncodeToString(sig0)},
			{PartyID: 1, Sig: base64.StdEncoding.EncodeToString(sig1)},
			{PartyID: 2, Sig: base64.StdEncoding.EncodeToString(sig2)},
			{PartyID: 3, Sig: base64.StdEncoding.EncodeToString(sig3)},
		},
	}

	filename := fmt.Sprintf("sigs_%s.yml", time.Now().Format("20060102150405"))

	yamlData, err := yaml.Marshal(sigShares)
	if err != nil {
		t.Errorf("Failed to marshal yaml: %v", err)
	}

	if err := os.WriteFile(filename, yamlData, 0644); err != nil {
		t.Errorf("Failed to save file: %v", err)
	}
}
