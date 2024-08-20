#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_enc_file="$jcrypto_this_dir/out-cms-auth-env-kek.pem"
jcrypto cms encrypt -i "$jcrypto_this_dir/in-cms-data.txt" -f PEM -c aes-128-gcm \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_enc_file"

# dump the content of the file (use openssl)
openssl asn1parse -i -in "$jcrypto_out_enc_file"

jcrypto_out_plain_file="$jcrypto_this_dir/out-cms-auth-env-kek-plain.txt"
jcrypto cms decrypt -i "$jcrypto_out_enc_file" -f PEM -c aes-128-gcm \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_plain_file"

cat "$jcrypto_out_plain_file"
echo ""

rm "$jcrypto_out_enc_file" "$jcrypto_out_plain_file"
