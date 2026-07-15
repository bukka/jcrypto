#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_cert_file="$jcrypto_data_dir/certificate.pem"
jcrypto_priv_key="$jcrypto_data_dir/private_key.pem"
jcrypto_in_file="$jcrypto_this_dir/in-cms-data.txt"
jcrypto_out_sig_file="$jcrypto_this_dir/out-cms-signed-detached.pem"
jcrypto_out_verify_file_from_jcrypto="$jcrypto_this_dir/out-cms-signed-detached-verify-jc.txt"
jcrypto_out_verify_file_from_ossl="$jcrypto_this_dir/out-cms-signed-detached-verify-ossl.txt"
jcrypto_out_ossl_sig_file="$jcrypto_this_dir/out-cms-signed-detached-ossl.pem"
jcrypto_out_ossl_verify_file_from_jcrypto="$jcrypto_this_dir/out-cms-signed-detached-ossl-verify-jc.txt"
jcrypto_out_ossl_verify_file_from_ossl="$jcrypto_this_dir/out-cms-signed-detached-ossl-verify-ossl.txt"

echo "JCRYPTO SIGN"
# A detached signature does not carry the content; the original file is supplied on verify.
jcrypto cms sign --detached -i "$jcrypto_in_file" -f PEM \
	    --signer-cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" -o "$jcrypto_out_sig_file"
jcrypto_dump_pem "$jcrypto_out_sig_file"

echo "OPENSSL SIGN"
# OpenSSL cms -sign is detached by default; -binary avoids content canonicalization.
jcrypto_openssl cms -sign -binary -in "$jcrypto_in_file" -outform PEM \
  -signer "$jcrypto_cert_file" -inkey "$jcrypto_priv_key" -out "$jcrypto_out_ossl_sig_file"
jcrypto_dump_pem "$jcrypto_out_ossl_sig_file"

# Detached verification needs the original content (-content for OpenSSL, --content for jcrypto).
echo "OPENSSL VERIFY OF OPENSSL"
jcrypto_openssl cms -verify -in "$jcrypto_out_ossl_sig_file" -inform PEM -binary -noverify \
  -content "$jcrypto_in_file" -out "$jcrypto_out_ossl_verify_file_from_ossl"
jcrypto_cat "$jcrypto_out_ossl_verify_file_from_ossl"

echo "OPENSSL VERIFY OF JCRYPTO"
jcrypto_openssl cms -verify -in "$jcrypto_out_sig_file" -inform PEM -binary -noverify \
  -content "$jcrypto_in_file" -out "$jcrypto_out_ossl_verify_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_ossl_verify_file_from_jcrypto"

echo "JCRYPTO VERIFY OF JCRYPTO"
jcrypto cms verify --detached --content "$jcrypto_in_file" -i "$jcrypto_out_sig_file" -f PEM \
	    -o "$jcrypto_out_verify_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_verify_file_from_jcrypto"

echo "JCRYPTO VERIFY OF OPENSSL"
jcrypto cms verify --detached --content "$jcrypto_in_file" -i "$jcrypto_out_ossl_sig_file" -f PEM \
	    -o "$jcrypto_out_verify_file_from_ossl"
jcrypto_cat "$jcrypto_out_verify_file_from_ossl"

rm $jcrypto_out_sig_file $jcrypto_out_verify_file_from_jcrypto $jcrypto_out_verify_file_from_ossl
rm $jcrypto_out_ossl_sig_file $jcrypto_out_ossl_verify_file_from_jcrypto $jcrypto_out_ossl_verify_file_from_ossl
