#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="secp256r1"
fi

jcrypto_priv_key_src="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_main.der"
jcrypto_pub_key_src="$jcrypto_data_dir/public_key_ec_${jcrypto_curve_name}_main.der"
jcrypto_priv_key="$jcrypto_tmp_dir/private_key_ec_${jcrypto_curve_name}_main.der"
jcrypto_pub_key="$jcrypto_tmp_dir/public_key_ec_${jcrypto_curve_name}_main.der"
jcrypto_data_file="$jcrypto_this_dir/in-pkey-data.txt"
jcrypto_server_pid_file="$jcrypto_tmp_dir/pkey-server-ec-pkcs11.pid"
jcrypto_server_port=8089
jcrypto_server_url="http://localhost:$jcrypto_server_port"

cp $jcrypto_priv_key_src $jcrypto_priv_key
cp $jcrypto_pub_key_src $jcrypto_pub_key

echo "JCRYPTO SERVER START"
echo "Use like curl -s -X POST --data-binary @'$jcrypto_data_file' $jcrypto_server_url/pkey/sign"

jcrypto pkey server start --pid-file "$jcrypto_server_pid_file" --port $jcrypto_server_port \
  -a SHA256withECDSA --private-key-file "$jcrypto_priv_key" --public-key-file "$jcrypto_pub_key"

#jcrypto pkey server stop --pid-file "$jcrypto_server_pid_file"
