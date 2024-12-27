# jCrypto TODO list

## Cipher
- is `AES128_CBC` correct format in OpenSSL?
- test and validate IV length
    - for example CTR accepts only 20 bytes
 
## CMS
- KEK secret key should be converted to binary when encoding so OpenSSL can decrypt it
  - OpenSSL cms app is using OPENSSL_hexstr2buf for this value so it does not match
- Add CMSEnvelop tests
- Add RecipientHandler tests
- Add RecipientInfoGeneratorFactory tests

## Mail
- Add SMIMEEnvelope tests

## PKey
- generate cert signer should not be just for ECDH
  - make it generic
