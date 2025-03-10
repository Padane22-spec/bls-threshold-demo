package keygen

// KeyShares 包含所有密钥分片和阈值公钥
type KeyShares struct {
	TotalParties int        `yaml:"total_parties"`
	Threshold    int        `yaml:"threshold"`
	ThresholdPK  string     `yaml:"threshold_public_key"` // 阈值公钥
	Shares       []KeyShare `yaml:"shares"`
}

type KeyShare struct {
	PartyID int    `yaml:"party_id"`
	Share   string `yaml:"share"`
}
