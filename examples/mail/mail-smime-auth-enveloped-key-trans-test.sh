#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_cert_file="$jcrypto_data_dir/certificate.pem"
jcrypto_priv_key="$jcrypto_data_dir/private_key.pem"

jcrypto_out_enc_file="$jcrypto_this_dir/out-smime-auth-env-kye-trans-enc.pem"
jcrypto_out_plain_file_from_jcrypto="$jcrypto_this_dir/out-smime-auth-env-kye-trans-plain-jc.txt"
jcrypto_out_plain_file_from_ossl="$jcrypto_this_dir/out-smime-auth-env-kye-trans-plain-ossl.txt"
jcrypto_out_ossl_enc_file="$jcrypto_this_dir/out-smime-auth-env-kye-trans-ossl-enc.pem"
jcrypto_out_ossl_plain_file_from_jcrypto="$jcrypto_this_dir/out-smime-auth-env-kye-trans-ossl-plain-jc.txt"
jcrypto_out_ossl_plain_file_from_ossl="$jcrypto_this_dir/out-smime-auth-env-kye-trans-ossl-plain-ossl.txt"

echo "JCRYPTO ENCRYPT"
jcrypto mail encrypt -i "$jcrypto_this_dir/in-message-body.txt" -c aes-256-gcm \
      --from 'Jakub<jakub@bukka.eu>' --to 'Lucas<lucas@bukka.eu>' --subject 'Test' \
	    --cert "$jcrypto_cert_file" -o "$jcrypto_out_enc_file"
jcrypto_dump_smime "$jcrypto_out_enc_file"

echo "OPENSSL ENCRYPT"
jcrypto_openssl cms -encrypt -in "$jcrypto_this_dir/in-message-body.txt" -out "$jcrypto_out_ossl_enc_file" \
  -outform SMIME -from 'Jakub<jakub@bukka.eu>' -to 'Lucas<lucas@bukka.eu>' -subject 'Test' \
  -recip "$jcrypto_cert_file" -aes-256-gcm
jcrypto_dump_smime "$jcrypto_out_ossl_enc_file"

echo "OPENSSL DECRYPT OF OPENSSL"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_ossl_enc_file" -inform SMIME -aes-256-gcm \
  -recip "$jcrypto_cert_file" -inkey "$jcrypto_priv_key" -out "$jcrypto_out_ossl_plain_file_from_ossl"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_ossl"

echo "OPENSSL DECRYPT OF JCRYPTO"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_enc_file" -inform SMIME -aes-256-gcm \
  -recip "$jcrypto_cert_file" -inkey "$jcrypto_priv_key" -out "$jcrypto_out_ossl_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF JCRYPTO"
jcrypto mail decrypt -i "$jcrypto_out_enc_file" -f PEM -c aes-256-gcm \
	    --cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" -o "$jcrypto_out_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF OPENSSL"
jcrypto mail decrypt -i "$jcrypto_out_ossl_enc_file" -f PEM -c aes-256-gcm \
	    --cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" -o "$jcrypto_out_plain_file_from_ossl"
jcrypto_cat "$jcrypto_out_plain_file_from_ossl"

rm $jcrypto_out_enc_file $jcrypto_out_plain_file_from_jcrypto $jcrypto_out_plain_file_from_ossl
rm $jcrypto_out_ossl_enc_file $jcrypto_out_ossl_plain_file_from_jcrypto $jcrypto_out_ossl_plain_file_from_ossl
