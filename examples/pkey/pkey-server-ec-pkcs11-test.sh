#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi
jcrypto_out_pub_key_file="$jcrypto_tmp_dir/out-pkey-ec-${jcrypto_curve_name}-pub-key-pkcs11.der"
jcrypto_data_file="$jcrypto_this_dir/in-pkey-data.txt"
jcrypto_server_pid_file="$jcrypto_tmp_dir/pkey-server-ec-pkcs11.pid"
jcrypto_server_port=8089
jcrypto_server_url="http://localhost:$jcrypto_server_port"

jcrypto_info
jcrypto_pkcs11_setup pkey-sign-verify

echo "JCRYPTO GENERATE KEY"
jcrypto pkey generate --public-key-file "$jcrypto_out_pub_key_file" --private-key-alias JavaTestSignVerifyECKey \
  --key-store-password 1234 --key-store-name PKCS11 --algorithm EC --parameters $jcrypto_curve_name \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

jcrypto_cat_b64 "$jcrypto_out_pub_key_file"

jcrypto_pkey_data=$(cat "$jcrypto_this_dir/in-pkey-data.txt")

echo "JCRYPTO SERVER START"
jcrypto pkey server start --pid-file "$jcrypto_server_pid_file" --port $jcrypto_server_port \
  -a SHA256withECDSA --private-key-alias JavaTestSignVerifyECKey --public-key-file "$jcrypto_out_pub_key_file" \
  --key-store-password 1234 --key-store-name PKCS11 \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

jcrypto_signature=$(curl -s -X POST --data-binary @"$jcrypto_data_file" $jcrypto_server_url/pkey/sign)

echo $jcrypto_signature

#jcrypto pkey server stop --pid-file "$jcrypto_server_pid_file"
