#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_enc_file="$jcrypto_this_dir/out-cms-auth-kek-enc.pem"
jcrypto_out_plain_file_from_jcrypto="$jcrypto_this_dir/out-cms-auth-kek-plain-jc.txt"

echo "JCRYPTO AUTHENTICATE"
jcrypto cms encrypt -i "$jcrypto_this_dir/in-cms-data.txt" -f PEM --content-type authenticated-data \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
	    --auth-attr 1.3.6.1.4.1.99999.1=authenticated-value \
      -o "$jcrypto_out_enc_file"
jcrypto_dump_pem "$jcrypto_out_enc_file"

echo "JCRYPTO VERIFY"
jcrypto cms decrypt -i "$jcrypto_out_enc_file" -f PEM --content-type authenticated-data \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_plain_file_from_jcrypto"

rm $jcrypto_out_enc_file $jcrypto_out_plain_file_from_jcrypto
