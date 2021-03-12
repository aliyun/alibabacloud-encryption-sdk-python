# AlibabaCloud Encryption Python SDK 示例

[加密/解密示例](src/basic_encryption.py)

[签名/验签示例](src/sign_verify/sign_verify_sample.py)

[多可用区示例](src/multi/multi_cmk_sample.py)

[托管数据密钥示例](src/provider/provider_sample.py)

[OSS数据保护示例](src/oss/oss_encryption_sample.py)

[数据库脱敏示例](src/rds/rds_sample.py)

运行示例

```shell
env ACCESS_KEY_ID="" \
  ACCESS_KEY_SECRET="" \
  other environments... \
  python <script_name>.py
```

参数说明

|环境变量|说明|示例值|
|---|---|---|
|ACCESS_KEY_ID|RAM访问密钥标识|0wNEpMMlzy7s****|
|ACCESS_KEY_SECRET|RAM访问密钥|PupkTg8jdmau1cXxYacgE736PJ****|
|AES_KEY_ARN|KMS AES密钥的阿里云资源名称|acs:kms:cn-hangzhou:123456:key/12345678-1234-1234-1234-123456789abc|
|RSA_SIGN_VERIFY_KEY_ARN|KMS RSA签名/验签密钥的阿里云资源名称|acs:kms:cn-hangzhou:123456:key/12345678-1234-1234-1234-123456789abc|
|RSA_SIGN_VERIFY_KEY_VERSION|KMS RSA签名/验签密钥版本号|12345678-1234-1234-1234-123456789abc|
|RSA_SIGN_VERIFY_PUBLIC_KEY|KMS RSA签名/验签密钥公钥PEM编码|-----BEGIN PUBLIC KEY-----<br/>MII****<br/>-----END PUBLIC KEY-----|
|RSA_SIGN_VERIFY_PUBLIC_CERT|KMS RSA签名/验签X.509证书PEM编码|-----BEGIN CERTIFICATE-----<br/>MII****<br/>-----END CERTIFICATE-----|