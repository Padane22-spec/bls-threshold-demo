package verify

type SigShares struct {
	TotalParties int        `yaml:"total_parties"`
	Threshold    int        `yaml:"threshold"`
	ThresholdPK  string     `yaml:"threshold_public_key"` // 阈值公钥
	Sigs         []SigShare `yaml:"sigs"`
}

type SigShare struct {
	PartyID int    `yaml:"party_id"`
	Sig     string `yaml:"threshold"`
}
