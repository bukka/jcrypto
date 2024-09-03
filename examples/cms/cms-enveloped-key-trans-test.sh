#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_cert_file="$jcrypto_data_dir/certificate.pem"
jcrypto_priv_key="$jcrypto_data_dir/private_key.pem"
jcrypto_out_enc_file="$jcrypto_this_dir/out-cms-env-key-trans-enc.pem"
jcrypto_out_plain_file_from_jcrypto="$jcrypto_this_dir/out-cms-env-key-trans-plain-jc.txt"
jcrypto_out_plain_file_from_ossl="$jcrypto_this_dir/out-cms-env-key-trans-plain-ossl.txt"
jcrypto_out_ossl_enc_file="$jcrypto_this_dir/out-cms-env-key-trans-ossl-enc.pem"
jcrypto_out_ossl_plain_file_from_jcrypto="$jcrypto_this_dir/out-cms-env-key-trans-ossl-plain-jc.txt"
jcrypto_out_ossl_plain_file_from_ossl="$jcrypto_this_dir/out-cms-env-key-trans-ossl-plain-ossl.txt"

echo "JCRYPTO ENCRYPT"
jcrypto cms encrypt -i "$jcrypto_this_dir/in-cms-data.txt" -f PEM -c aes-128-cbc \
	    --cert "$jcrypto_cert_file" -o "$jcrypto_out_enc_file"
jcrypto_dump_pem "$jcrypto_out_enc_file"

echo "OPENSSL ENCRYPT"
jcrypto_openssl cms -encrypt -in "$jcrypto_this_dir/in-cms-data.txt" -out "$jcrypto_out_ossl_enc_file" -outform PEM \
  -recip "$jcrypto_cert_file" -aes-128-cbc
jcrypto_dump_pem "$jcrypto_out_ossl_enc_file"

echo "OPENSSL DECRYPT OF OPENSSL"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_ossl_enc_file" -inform PEM -aes-128-cbc \
   -recip "$jcrypto_cert_file" -inkey "$jcrypto_priv_key" -out "$jcrypto_out_ossl_plain_file_from_ossl"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_ossl"

echo "OPENSSL DECRYPT OF JCRYPTO"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_enc_file" -inform PEM -aes-128-cbc \
  -recip "$jcrypto_cert_file" -inkey "$jcrypto_priv_key" -out "$jcrypto_out_ossl_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF JCRYPTO"
jcrypto cms decrypt -i "$jcrypto_out_enc_file" -f PEM -c aes-128-cbc \
	    --cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" -o "$jcrypto_out_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF OPENSSL"
jcrypto cms decrypt -i "$jcrypto_out_ossl_enc_file" -f PEM -c aes-128-cbc \
	    --cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" -o "$jcrypto_out_plain_file_from_ossl"
jcrypto_cat "$jcrypto_out_plain_file_from_ossl"

rm $jcrypto_out_enc_file $jcrypto_out_plain_file_from_jcrypto $jcrypto_out_plain_file_from_ossl
rm $jcrypto_out_ossl_enc_file $jcrypto_out_ossl_plain_file_from_jcrypto $jcrypto_out_ossl_plain_file_from_ossl
