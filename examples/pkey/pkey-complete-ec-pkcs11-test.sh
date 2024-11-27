#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi
jcrypto_other_pub_key="$jcrypto_data_dir/public_key_ec_${jcrypto_curve_name}_main.der"
jcrypto_out_sig_file="$jcrypto_tmp_dir/out-pkey-ec-basic-sig.txt"
jcrypto_out_secret_file="$jcrypto_tmp_dir/out-pkey-ec-basic-secret.txt"

jcrypto_pkcs11_setup pkey-complete

echo "JCRYPTO GENERATE KEY"
jcrypto pkey generate --private-key-alias JavaTestCompleteECKey \
  --key-store-password 1234 --key-store-name PKCS11 --algorithm EC --parameters $jcrypto_curve_name \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

echo "JCRYPTO SIGN"
jcrypto pkey sign -i "$jcrypto_this_dir/in-pkey-data.txt" -a SHA256withECDSA -o "$jcrypto_out_sig_file" \
  --private-key-alias JavaTestCompleteECKey --key-store-password 1234 --key-store-name PKCS11 \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

echo "JCRYPTO VERIFY"
jcrypto pkey verify -i "$jcrypto_this_dir/in-pkey-data.txt" -a SHA256withECDSA \
  --signature-file "$jcrypto_out_sig_file" --public-key-alias JavaTestCompleteECKey \
  --key-store-password 1234 --key-store-name PKCS11 \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

echo "JCRYPTO DERIVE"
jcrypto pkey derive -a ECDH -o "$jcrypto_out_secret_file" \
  --public-key-file "$jcrypto_other_pub_key" --private-key-alias JavaTestCompleteECKey \
  --key-store-password 1234 --key-store-name PKCS11 \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

jcrypto_cat "$jcrypto_out_secret_file" | base64
