#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_main_shared_secret="$jcrypto_tmp_dir/out-pkey-ecdh-main-shared-secret.txt"
jcrypto_out_peer_shared_secret="$jcrypto_tmp_dir/out-pkey-ecdh-peer-shared-secret.txt"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi
jcrypto_main_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_main.der"
jcrypto_main_pub_key="$jcrypto_data_dir/public_key_ec_${jcrypto_curve_name}_main.der"
jcrypto_peer_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_peer.der"
jcrypto_peer_pub_key="$jcrypto_data_dir/public_key_ec_${jcrypto_curve_name}_peer.der"

echo "JCRYPTO DERIVE MAIN"
jcrypto pkey derive -a ECDH -o "$jcrypto_out_main_shared_secret" \
  --private-key-file "$jcrypto_main_priv_key" --public-key-file "$jcrypto_peer_pub_key"

echo "JCRYPTO DERIVE PEER"
jcrypto pkey derive -a ECDH -o "$jcrypto_out_peer_shared_secret" \
  --private-key-file "$jcrypto_peer_priv_key" --public-key-file "$jcrypto_main_pub_key"

echo "JCRYPTO DERIVED SECRETS (main, peer)"
jcrypto_cat_b64 "$jcrypto_out_main_shared_secret"
jcrypto_cat_b64 "$jcrypto_out_peer_shared_secret"

rm "$jcrypto_out_main_shared_secret" "$jcrypto_out_peer_shared_secret"
