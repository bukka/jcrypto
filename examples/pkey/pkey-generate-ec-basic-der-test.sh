#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi
jcrypto_out_pub_key_file="$jcrypto_tmp_dir/out-pkey-ec-${jcrypto_curve_name}-pub-key-basic.der"
jcrypto_out_priv_key_file="$jcrypto_tmp_dir/out-pkey-ec-${jcrypto_curve_name}-priv-key-basic.der"

echo "JCRYPTO GENERATE KEY"
jcrypto pkey generate --public-key-file "$jcrypto_out_pub_key_file" --private-key-file "$jcrypto_out_priv_key_file" \
  --algorithm EC --parameters $jcrypto_curve_name

jcrypto_cat_b64 "$jcrypto_out_pub_key_file"
jcrypto_cat_b64 "$jcrypto_out_priv_key_file"
