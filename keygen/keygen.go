package keygen

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"time"

	bls "github.com/IBM/TSS/mpc/bls"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Keygen 结构体用于管理密钥生成过程
type Keygen struct {
	n         int         // 参与方总数
	threshold int         // 阈值数量
	parties   []*bls.TBLS // 参与方列表
	shares    [][]byte    // 密钥分片列表
}

// NewKeygen 创建一个新的 Keygen 实例
// n: 参与方总数
// threshold: 阈值数量
func NewKeygen(n int, threshold int) *Keygen {
	return &Keygen{
		n:         n,
		threshold: threshold,
	}
}

// GenerateParties 生成所有参与方实例
func (k *Keygen) GenerateParties() {
	k.parties = generateTBLSParties(k.n, k.threshold)
}

// GenerateShares 为所有参与方生成密钥分片
func (k *Keygen) GenerateShares() {
	k.shares = generateShares(k.parties)
}

// GetPk 获取指定参与方的公钥
// id: 参与方ID
// 返回: 公钥字节数组
func (k *Keygen) GetPk(id int) []byte {
	pk, err := k.parties[id].ThresholdPK()
	if err != nil {
		fmt.Println("Error getting threshold public key:", err)
		return nil
	}
	return pk
}

// SaveKeysToYAML 将生成的密钥保存为 YAML 文件
func (k *Keygen) SaveKeysToYAML() error {

	if len(k.parties) == 0 {
		return fmt.Errorf("no parties provided")
	}

	// 获取阈值公钥
	thresholdPK, err := k.parties[0].ThresholdPK()
	if err != nil {
		return fmt.Errorf("failed to get threshold public key: %v", err)
	}

	keyShares := KeyShares{
		Threshold:    k.threshold,
		TotalParties: k.n,
		ThresholdPK:  base64.StdEncoding.EncodeToString(thresholdPK),
		Shares:       make([]KeyShare, len(k.parties)),
	}

	// 收集每个参与方的密钥分片
	for i, _ := range k.parties {

		keyShares.Shares[i] = KeyShare{
			PartyID: i,
			Share:   base64.StdEncoding.EncodeToString(k.shares[i]),
		}
	}

	// 将结构序列化为 YAML
	yamlData, err := yaml.Marshal(keyShares)
	if err != nil {
		return fmt.Errorf("failed to marshal to YAML: %v", err)
	}

	// 写入文件
	// 生成包含当前时间的文件名
	now := time.Now()
	filename := fmt.Sprintf("config_%s.yml", now.Format("20060102150405"))
	err = os.WriteFile(filename, yamlData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write YAML file: %v", err)
	}

	return nil
}

// generateTBLSParties 生成指定数量的 TBLS 参与方
// n: 参与方总数
// threshold: 阈值数量
// 返回: TBLS 参与方列表
func generateTBLSParties(n int, threshold int) []*bls.TBLS {
	parties := make([]*bls.TBLS, n)
	for i := range n {
		parties[i] = newTBLSParty(i)
	}
	for i := range n {
		initTBLSParty(i, parties, threshold)
	}
	return parties
}

// generateShares 为所有参与方生成密钥分片
// parties: TBLS 参与方列表
// 返回: 密钥分片列表
func generateShares(parties []*bls.TBLS) [][]byte {
	shares := make([][]byte, len(parties))
	var wg sync.WaitGroup
	wg.Add(len(parties))

	for i, p := range parties {
		go func(i int, p *bls.TBLS) {
			defer wg.Done()
			share, err := p.KeyGen(context.Background())
			if err != nil {
				fmt.Println("Error generating key:", err)
				return
			}

			// Save the share for later use
			shares[i] = share
		}(i, p)
	}

	wg.Wait()
	return shares
}

// initTBLSParty 初始化单个 TBLS 参与方
// id: 参与方ID
// parties: 所有参与方列表
// threshold: 阈值数量
func initTBLSParty(id int, parties []*bls.TBLS, threshold int) {
	party := parties[id]
	party.Init(getIDs(parties), threshold, createMessageHandler(id, parties))
}

// createMessageHandler 创建消息处理函数
// id: 参与方ID
// parties: 所有参与方列表
// 返回: 消息处理函数
func createMessageHandler(id int, parties []*bls.TBLS) func([]byte, bool, uint16) {
	return func(msg []byte, isBroadcast bool, to uint16) {
		idUint16 := uint16(id)
		if isBroadcast {
			for i, p := range parties {
				if i != id {
					p.OnMsg(msg, idUint16, isBroadcast)
				}
			}
		} else {
			parties[int(to)].OnMsg(msg, idUint16, isBroadcast)
		}
	}
}

// getIDs 获取所有参与方的ID列表
// parties: 所有参与方列表
// 返回: ID列表
func getIDs(parties []*bls.TBLS) []uint16 {
	ids := make([]uint16, len(parties))
	for i, party := range parties {
		ids[i] = party.Party
	}
	return ids
}

// newTBLSParty 创建新的 TBLS 参与方
// id: 参与方ID
// 返回: TBLS 参与方实例
func newTBLSParty(id int) *bls.TBLS {
	party := &bls.TBLS{
		Logger: logger(fmt.Sprintf("p%d", id), "utils"),
		Party:  uint16(id),
	}
	return party
}

// logger 创建日志记录器
// id: 参与方ID
// testName: 测试名称
// 返回: 日志记录器实例
func logger(id string, testName string) bls.Logger {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	logger = logger.With(zap.String("t", testName)).With(zap.String("id", id))
	return logger.Sugar()
}
