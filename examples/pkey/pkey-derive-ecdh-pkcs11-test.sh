#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"


jcrypto_out_main_shared_secret="$jcrypto_tmp_dir/out-pkey-p11-ecdh-main-shared-secret.txt"
jcrypto_out_peer_shared_secret="$jcrypto_tmp_dir/out-pkey-p11-ecdh-peer-shared-secret.txt"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi
jcrypto_peer_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_peer.der"
jcrypto_peer_pub_key="$jcrypto_data_dir/public_key_ec_${jcrypto_curve_name}_peer.der"
jcrypto_out_pub_key_file="$jcrypto_tmp_dir/out-pkey-p11-ec-${jcrypto_curve_name}-pub-key-pkcs11.der"

jcrypto_pkcs11_setup pkey-sign-verify

echo "JCRYPTO GENERATE KEY"
jcrypto pkey generate --public-key-file "$jcrypto_out_pub_key_file" --private-key-alias JavaTestDeriveECKey \
  --key-store-password 1234 --key-store-name PKCS11 --algorithm EC --parameters $jcrypto_curve_name \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

jcrypto_cat_b64 "$jcrypto_out_pub_key_file"

echo "JCRYPTO DERIVE MAIN"
jcrypto pkey derive -a ECDH -o "$jcrypto_out_main_shared_secret" \
  --public-key-file "$jcrypto_peer_pub_key" --private-key-alias JavaTestDeriveECKey \
  --key-store-password 1234 --key-store-name PKCS11 \
  --provider-name SunPKCS11 --provider-config-file "$jcrypto_pkcs11_java_config"

echo "JCRYPTO DERIVE PEER"
jcrypto pkey derive -a ECDH -o "$jcrypto_out_peer_shared_secret" \
  --private-key-file "$jcrypto_peer_priv_key" --public-key-file "$jcrypto_out_pub_key_file"

echo "JCRYPTO DERIVED SECRETS (main, peer)"
jcrypto_cat_b64 "$jcrypto_out_main_shared_secret"
jcrypto_cat_b64 "$jcrypto_out_peer_shared_secret"

rm "$jcrypto_out_main_shared_secret" "$jcrypto_out_peer_shared_secret" "$jcrypto_out_pub_key_file"
