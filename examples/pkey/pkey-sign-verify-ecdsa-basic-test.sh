#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_sig_file="$jcrypto_this_dir/out-pkey-ecdsa-basic-sig.txt"


jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi
jcrypto_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_jc.der"
jcrypto_pub_key="$jcrypto_data_dir/public_key_ec_${jcrypto_curve_name}_jc.der"

echo "JCRYPTO SIGN"
jcrypto pkey sign -i "$jcrypto_this_dir/in-pkey-data.txt" -a ECDSA -o "$jcrypto_out_sig_file" \
  --private-key-file "$jcrypto_priv_key"

echo "JCRYPTO VERIFY"
jcrypto pkey verify -i "$jcrypto_this_dir/in-pkey-data.txt" -a ECDSA --signature-file "$jcrypto_out_sig_file" \
  --public-key-file "$jcrypto_pub_key"

rm "$jcrypto_out_sig_file"
