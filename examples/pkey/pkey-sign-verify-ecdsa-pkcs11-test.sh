#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi
jcrypto_out_sig_file="$jcrypto_tmp_dir/out-pkey-ecdsa-basic-sig.txt"
jcrypto_out_pub_key_file="$jcrypto_tmp_dir/out-pkey-ec-${jcrypto_curve_name}-pub-key-pkcs11.der"

jcrypto_pkcs11_setup pkey-sign-verify

echo "JCRYPTO GENERATE KEY"
jcrypto pkey generate --public-key-file "$jcrypto_out_pub_key_file" --private-key-alias JavaTestSignVerifyECKey \
  --key-store-password 1234 --key-store-name PKCS11 --algorithm EC --parameters $jcrypto_curve_name \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

jcrypto_cat_b64 "$jcrypto_out_pub_key_file"

echo "JCRYPTO SIGN"
jcrypto pkey sign -i "$jcrypto_this_dir/in-pkey-data.txt" -a SHA256withECDSA -o "$jcrypto_out_sig_file" \
  --private-key-alias JavaTestSignVerifyECKey --key-store-password 1234 --key-store-name PKCS11 \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

echo "JCRYPTO VERIFY"
jcrypto pkey verify -i "$jcrypto_this_dir/in-pkey-data.txt" -a SHA256withECDSA \
  --signature-file "$jcrypto_out_sig_file" --public-key-file "$jcrypto_out_pub_key_file" \
  --key-store-password 1234 --key-store-name PKCS11 \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

