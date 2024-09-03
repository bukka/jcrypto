#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_enc_file="$jcrypto_this_dir/out-cms-env-kek-enc.pem"
jcrypto_out_plain_file_from_jcrypto="$jcrypto_this_dir/out-cms-env-kek-plain-jc.txt"
jcrypto_out_plain_file_from_ossl="$jcrypto_this_dir/out-cms-env-kek-plain-ossl.txt"
jcrypto_out_ossl_enc_file="$jcrypto_this_dir/out-cms-env-kek-ossl-enc.pem"
jcrypto_out_ossl_plain_file_from_jcrypto="$jcrypto_this_dir/out-cms-env-kek-ossl-plain-jc.txt"
jcrypto_out_ossl_plain_file_from_ossl="$jcrypto_this_dir/out-cms-env-kek-ossl-plain-ossl.txt"

echo "JCRYPTO ENCRYPT"
jcrypto cms encrypt -i "$jcrypto_this_dir/in-cms-data.txt" -f PEM -c aes-128-cbc \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_enc_file"
jcrypto_dump_pem "$jcrypto_out_enc_file"

echo "OPENSSL ENCRYPT"
jcrypto_openssl cms -encrypt -in "$jcrypto_this_dir/in-cms-data.txt" -out "$jcrypto_out_ossl_enc_file" -outform PEM \
  -secretkey 000102030405060708090A0B0C0D0E0F -secretkeyid C0FEE0 -aes-128-cbc
jcrypto_dump_pem "$jcrypto_out_ossl_enc_file"

echo "OPENSSL DECRYPT OF OPENSSL"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_ossl_enc_file" -inform PEM -aes-128-cbc \
   -secretkey 000102030405060708090A0B0C0D0E0F -secretkeyid C0FEE0 -out "$jcrypto_out_ossl_plain_file_from_ossl"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_ossl"

echo "OPENSSL DECRYPT OF JCRYPTO"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_enc_file" -inform PEM -aes-128-cbc \
  -secretkey 000102030405060708090A0B0C0D0E0F -secretkeyid C0FEE0 -out "$jcrypto_out_ossl_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF JCRYPTO"
jcrypto cms decrypt -i "$jcrypto_out_enc_file" -f PEM -c aes-128-cbc \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF OPENSSL"
jcrypto cms decrypt -i "$jcrypto_out_ossl_enc_file" -f PEM -c aes-128-cbc \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_plain_file_from_ossl"
jcrypto_cat "$jcrypto_out_plain_file_from_ossl"

rm $jcrypto_out_enc_file $jcrypto_out_plain_file_from_jcrypto $jcrypto_out_plain_file_from_ossl
rm $jcrypto_out_ossl_enc_file $jcrypto_out_ossl_plain_file_from_jcrypto $jcrypto_out_ossl_plain_file_from_ossl
