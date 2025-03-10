# BLS门限签名系统

## 项目概述

这是一个基于BLS（Boneh-Lynn-Shacham）算法的门限签名系统实现demo，根据[IBM/TSS/mpc/bls](https://github.com/IBM/TSS)实现。支持密钥生成、分布式签名和签名验证功能。该系统允许多个参与方共同持有一个密钥，并要求至少达到指定阈值数量的参与方才能生成有效签名，从而提高系统的安全性和可用性。

## 功能特点

- 密钥生成：支持生成分布式密钥，并将密钥分片分发给各参与方
- 门限签名：支持多方协作生成签名，满足阈值要求
- 签名验证：验证聚合签名的有效性
- YAML配置：使用YAML格式存储和管理密钥分片和签名信息
- 灵活的阈值设置：可自定义参与方数量和阈值要求

## 项目结构
```
project/
├── keygen/           # 密钥生成模块
│   ├── keygen.go
│   ├── keygen_test.go
│   └── yaml_serialization.go
├── sign/             # 签名模块
│   ├── sign.go
│   ├── sign_test.go
│   └── yaml_serialization.go
├── verify/           # 验证模块
│   ├── verify.go
│   ├── verify_test.go
│   └── yaml_serialization.go
├── go.mod
└── README.md
```

## 安装指南
```
# 克隆仓库
git clone https://github.com/Padane22-spec/bls-threshold-demo
cd bls-threshold-demo

# 安装依赖
go mod download
```

## 使用方法

### 1.密钥生成

```
// 创建一个新的密钥生成器，参数为：参与方数量和阈值
kg := keygen.NewKeygen(4, 3)

// 生成参与方
kg.GenerateParties()

// 生成密钥分片
kg.GenerateShares()

// 保存密钥到YAML文件
err := kg.SaveKeysToYAML()
if err != nil {
    log.Fatalf("保存密钥失败: %v", err)
}
```

### 2.签名

```
// 创建签名者实例，从配置文件加载密钥分片
signer := sign.NewSigner("./config_0.yml")

// 对消息进行签名
message := []byte("要签名的消息")
digest := sha256.Sum256(message)
signature, err := signer.Sign(digest[:])
if err != nil {
    log.Fatalf("签名失败: %v", err)
}
```

### 3.签名验证

```
// 创建验证者实例，从配置文件加载阈值公钥
verifier := verify.NewVerifier("sigs.yml")

// 验证签名
message := []byte("要验证的消息")
digest := sha256.Sum256(message)
isValid := verifier.Verify(digest[:], signatures, partyIDs)
if isValid {
    fmt.Println("签名验证成功")
} else {
    fmt.Println("签名验证失败")
}
```

## 配置文件格式
### 密钥配置文件
```
total_parties: 4
threshold: 3
threshold_public_key: "base64编码的阈值公钥"
shares:
  - party_id: 0
    share: "base64编码的密钥分片"
  - party_id: 1
    share: "base64编码的密钥分片"
  # ...其他参与方的密钥分片
```

### 签名配置文件
```
total_parties: 4
threshold: 3
threshold_public_key: "base64编码的阈值公钥"
sigs:
  - party_id: 0
    threshold: "base64编码的签名分片"
  - party_id: 1
    threshold: "base64编码的签名分片"
  # ...其他参与方的签名分片
```

## 技术依赖
https://github.com/IBM/TSS - BLS门限签名算法实现

## 安全注意事项
- 私钥分片应妥善保管，避免泄露
- 在生产环境中，应使用安全的通道传输密钥分片
- 建议定期更新密钥，提高系统安全性

## 许可证
本项目采用 MIT 许可证