# jCrypto TODO list

## Cipher
- is `AES128_CBC` correct format in OpenSSL?
- test and validate IV length
    - for example CTR accepts only 20 bytes
 
## CMS
- Add CMSEnvelop tests
- Add RecipientHandler tests
- Add RecipientInfoGeneratorFactory tests

## Mail
- Add SMIMEEnvelope tests

## PKey
- generate cert signer should not be just for ECDH
  - make it generic
