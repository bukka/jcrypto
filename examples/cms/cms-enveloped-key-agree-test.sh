#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="prime256v1"
fi
jcrypto_orig_cert_file="$jcrypto_data_dir/certificate_ec_${jcrypto_curve_name}_orig.pem"
jcrypto_orig_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_orig.pem"
jcrypto_orig_priv_ec_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_orig_ec.pem"
jcrypto_recip_cert_file="$jcrypto_data_dir/certificate_ec_${jcrypto_curve_name}_recip.pem"
jcrypto_recip_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_recip.pem"
jcrypto_recip_priv_ec_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_recip_ec.pem"

jcrypto_out_enc_file="$jcrypto_this_dir/out-cms-env-kye-agree-enc.pem"
jcrypto_out_plain_file_from_jcrypto="$jcrypto_this_dir/out-cms-env-kye-agree-plain-jc.txt"
jcrypto_out_plain_file_from_ossl="$jcrypto_this_dir/out-cms-env-kye-agree-plain-ossl.txt"
jcrypto_out_ossl_enc_file="$jcrypto_this_dir/out-cms-env-kye-agree-ossl-enc.pem"
jcrypto_out_ossl_plain_file_from_jcrypto="$jcrypto_this_dir/out-cms-env-kye-agree-ossl-plain-jc.txt"
jcrypto_out_ossl_plain_file_from_ossl="$jcrypto_this_dir/out-cms-env-kye-agree-ossl-plain-ossl.txt"

echo "JCRYPTO ENCRYPT"
jcrypto cms encrypt -i "$jcrypto_this_dir/in-cms-data.txt" -c aes-128-cbc \
	    --recipient-cert "$jcrypto_recip_cert_file" --sender-cert "$jcrypto_orig_cert_file" \
	    --private-key "$jcrypto_orig_priv_key" -o "$jcrypto_out_enc_file"
jcrypto_dump_pem "$jcrypto_out_enc_file"

echo "OPENSSL ENCRYPT"
jcrypto_openssl cms -encrypt -in "$jcrypto_this_dir/in-cms-data.txt" -out "$jcrypto_out_ossl_enc_file" \
  -outform PEM -recip "$jcrypto_recip_cert_file" -aes-128-cbc
# The below is not currently supported and crashes openssl because only pubkey empheral key is supported for encryption
#jcrypto_openssl cms -encrypt -in "$jcrypto_this_dir/in-cms-data.txt" -out "$jcrypto_out_ossl_enc_file" \
#  -outform PEM -recip "$jcrypto_recip_cert_file" -inkey "$jcrypto_orig_priv_ec_key" \
#  -originator "$jcrypto_orig_cert_file" -aes-128-cbc
jcrypto_dump_pem "$jcrypto_out_ossl_enc_file"

echo "OPENSSL DECRYPT OF OPENSSL"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_ossl_enc_file" -inform PEM -aes-128-cbc \
  -inkey "$jcrypto_recip_priv_ec_key" -out "$jcrypto_out_ossl_plain_file_from_ossl"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_ossl"

echo "OPENSSL DECRYPT OF JCRYPTO"
jcrypto_openssl cms -decrypt -in "$jcrypto_out_ossl_enc_file" -inform PEM -aes-128-cbc \
  -originator "$jcrypto_orig_cert_file" -inkey "$jcrypto_recip_priv_ec_key" \
  -out "$jcrypto_out_ossl_plain_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_ossl_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF JCRYPTO"
jcrypto cms decrypt -i "$jcrypto_out_enc_file" -f PEM -c aes-128-cbc -o "$jcrypto_out_plain_file_from_jcrypto" \
	--recipient-cert "$jcrypto_recip_cert_file" --private-key "$jcrypto_recip_priv_key"
jcrypto_cat "$jcrypto_out_plain_file_from_jcrypto"

echo "JCRYPTO DECRYPT OF OPENSSL"
jcrypto cms decrypt -i "$jcrypto_out_ossl_enc_file" -f PEM -c aes-128-cbc -o "$jcrypto_out_plain_file_from_ossl" \
	--recipient-cert "$jcrypto_recip_cert_file" --private-key "$jcrypto_recip_priv_key"
jcrypto_cat "$jcrypto_out_plain_file_from_ossl"

rm $jcrypto_out_enc_file $jcrypto_out_plain_file_from_jcrypto $jcrypto_out_plain_file_from_ossl
rm $jcrypto_out_ossl_enc_file $jcrypto_out_ossl_plain_file_from_jcrypto $jcrypto_out_ossl_plain_file_from_ossl
