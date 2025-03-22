#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_enc_file="$jcrypto_tmp_dir/out-enveloped-content-type-for-aes-gcm.pem"

echo "JCRYPTO ENCRYPT"
jcrypto cms encrypt -i "$jcrypto_this_dir/in-cms-data.txt" -f PEM -c aes-128-gcm \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      --content-type enveloped-data -o "$jcrypto_out_enc_file"
jcrypto_dump_pem "$jcrypto_out_enc_file"
