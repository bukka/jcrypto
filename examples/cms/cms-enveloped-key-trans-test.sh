#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_cert_file="$jcrypto_this_dir/certificate.pem"
jcrypto_priv_key="$jcrypto_this_dir/private_key.pem"

jcrypto_out_enc_file="$jcrypto_this_dir/out-cms-env-key-trans.pem"
jcrypto cms encrypt -i "$jcrypto_this_dir/in-cms-data.txt" -f PEM -c aes-128-cbc \
	    --cert "$jcrypto_cert_file" -o "$jcrypto_out_enc_file"

# dump the content of the file (use openssl)
openssl asn1parse -i -in "$jcrypto_out_enc_file"

jcrypto_out_plain_file="$jcrypto_this_dir/out-cms-env-key-trans-plain.txt"
jcrypto cms decrypt -i "$jcrypto_out_enc_file" -f PEM -c aes-128-cbc \
	    --cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" \
      -o "$jcrypto_out_plain_file"

cat "$jcrypto_out_plain_file"
echo ""

rm "$jcrypto_out_enc_file" "$jcrypto_out_plain_file"
