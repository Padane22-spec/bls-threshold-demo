package sign

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/IBM/TSS/mpc/bls"
	"gopkg.in/yaml.v3"
)

// Signer 结构体用于管理BLS门限签名的参与方
// 每个参与方持有一个私钥分片,可以独立生成签名分片
type Signer struct {
	n         int       // 总参与方数量
	threshold int       // 门限值,需要至少threshold个签名分片才能生成有效签名
	partyId   int       // 当前参与方ID,用于标识不同的参与方
	party     *bls.TBLS // BLS门限签名实例,用于生成签名分片
	share     []byte    // 签名私钥分片,由密钥生成阶段分配
}

// Sign 使用私钥分片对消息进行签名
// message: 待签名的消息
// 返回: 签名分片和错误信息
func (s *Signer) Sign(message []byte) ([]byte, error) {
	sig, err := s.party.Sign(context.Background(), message)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// NewSigner 从配置文件创建一个新的签名者实例
// configFile: 包含密钥分片信息的配置文件路径
// 返回: 签名者实例
func NewSigner(configFile string) *Signer {
	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error reading config file: %s\n", err)
		return nil
	}

	var ks KeyShares
	if err := yaml.Unmarshal(yamlFile, &ks); err != nil {
		fmt.Printf("Error unmarshaling config: %s\n", err)
		return nil
	}

	if len(ks.Shares) == 0 {
		fmt.Println("No shares found")
		return nil
	}

	var signer Signer
	signer.n = ks.TotalParties
	signer.threshold = ks.Threshold
	signer.share, err = base64.StdEncoding.DecodeString(ks.Shares[0].Share)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	signer.partyId = ks.Shares[0].PartyID
	signer.party = newTBLSParty(signer.partyId)
	signer.party.SetShareData(signer.share)
	return &signer
}

// newTBLSParty 创建一个新的BLS门限签名参与方实例
// id: 参与方ID
// 返回: BLS门限签名参与方实例
func newTBLSParty(id int) *bls.TBLS {
	party := &bls.TBLS{
		// Logger: logger(fmt.Sprintf("p%d", id), "utils"),
		Party: uint16(id),
	}
	return party
}
