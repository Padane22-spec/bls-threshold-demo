package sign

// KeyShares 包含所有密钥分片和阈值公钥
type KeyShares struct {
	TotalParties int        `mapstructure:"total_parties"`
	Threshold    int        `mapstructure:"threshold"`
	ThresholdPK  string     `mapstructure:"threshold_public_key"` // 阈值公钥
	Shares       []KeyShare `mapstructure:"shares"`
}

type KeyShare struct {
	PartyID int    `mapstructure:"party_id"`
	Share   string `mapstructure:"share"`
}

type SigShares struct {
	TotalParties int        `mapstructure:"total_parties"`
	Threshold    int        `mapstructure:"threshold"`
	ThresholdPK  string     `mapstructure:"threshold_public_key"` // 阈值公钥
	Sigs         []SigShare `mapstructure:"sigs"`
}

type SigShare struct {
	PartyID int    `mapstructure:"party_id"`
	Sig     string `mapstructure:"sig"`
}
