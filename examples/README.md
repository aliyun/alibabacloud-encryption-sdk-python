# AlibabaCloud Encryption Python SDK Sample Code

[Basic Encryption Example](src/basic_encryption.py)

[Sign/Verify Example](src/sign_verify/sign_verify_sample.py)

[Multi-Region Example](src/multi/multi_cmk_sample.py)

[Key Provider Example](src/provider/provider_sample.py)

[OSS Encryption Example](src/oss/oss_encryption_sample.py)

[Encrypt RDS Sensitive Data Example](src/rds/rds_sample.py)

How to run example

```shell
env ACCESS_KEY_ID="" \
  ACCESS_KEY_SECRET="" \
  other environments... \
  python <script_name>.py
```

Environment Reference

|Environment|Description|Example|
|---|---|---|
|ACCESS_KEY_ID|The AccessKey ID provided to you by Alibaba Cloud.|0wNEpMMlzy7s****|
|ACCESS_KEY_SECRET|The AccessKey Secret provided to you by Alibaba Cloud.|PupkTg8jdmau1cXxYacgE736PJ****|
|AES_KEY_ARN|The Alibaba Cloud Resource Name (ARN) of the AES CMK.|acs:kms:cn-hangzhou:123456:key/12345678-1234-1234-1234-123456789abc|
|RSA_SIGN_VERIFY_KEY_ARN|The Alibaba Cloud Resource Name (ARN) of the RSA CMK.|acs:kms:cn-hangzhou:123456:key/12345678-1234-1234-1234-123456789abc|
|RSA_SIGN_VERIFY_KEY_VERSION|The ID of the RSA primary key version.|12345678-1234-1234-1234-123456789abc|
|RSA_SIGN_VERIFY_PUBLIC_KEY|The PublicKey of the RSA primary key.|-----BEGIN PUBLIC KEY-----<br/>MII****<br/>-----END PUBLIC KEY-----|
|RSA_SIGN_VERIFY_PUBLIC_CERT|The X.509 Certificate of the RSA primary key.|-----BEGIN CERTIFICATE-----<br/>MII****<br/>-----END CERTIFICATE-----|