package verify

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/IBM/TSS/mpc/bls"
	"gopkg.in/yaml.v3"
)

// Verifier 结构体用于管理BLS门限签名的验证
type Verifier struct {
	v           *bls.Verifier // BLS验证器实例
	thresholdPK []byte        // 阈值公钥
}

// NewVerifier 从配置文件创建一个新的验证者实例
// fileName: 配置文件路径
// 返回: 验证者实例
func NewVerifier(fileName string) *Verifier {
	// 读取配置文件
	yamlFile, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Printf("Error reading config file: %s\n", err)
		return nil
	}

	// 解析YAML配置
	var sigShares SigShares
	if err := yaml.Unmarshal(yamlFile, &sigShares); err != nil {
		fmt.Printf("Error unmarshaling config: %s\n", err)
		return nil
	}

	fmt.Printf("sigShares: %+v\n", sigShares)

	// 解码阈值公钥
	pk, err := base64.StdEncoding.DecodeString(sigShares.ThresholdPK)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	// 初始化BLS验证器
	var v_bls bls.Verifier
	v_bls.Init(pk)
	verifier := &Verifier{
		v:           &v_bls,
		thresholdPK: pk,
	}

	return verifier
}

// Verify 验证聚合签名是否有效
// msg: 待验证的消息
// sigs: 签名分片列表
// ids: 签名者ID列表
// 返回: 验证结果
func (v *Verifier) Verify(msg []byte, sigs [][]byte, ids []uint16) bool {
	// 聚合签名分片
	tresholdSig, err := v.AggregateSignatures(sigs, ids)
	if err != nil {
		fmt.Println(err)
		return false
	}

	// 验证聚合签名
	err = v.v.Verify(msg, tresholdSig)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

// AggregateSignatures 聚合多个签名分片
// sigs: 签名分片列表
// ids: 签名者ID列表
// 返回: 聚合后的签名和错误信息
func (v *Verifier) AggregateSignatures(sigs [][]byte, ids []uint16) ([]byte, error) {
	// 检查输入参数
	if len(sigs) == 0 || len(ids) == 0 {
		return nil, errors.New("sigs or ids is empty")
	}

	return v.v.AggregateSignatures(sigs, ids)
}
