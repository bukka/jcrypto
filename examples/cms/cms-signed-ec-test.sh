#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_cert_file="$jcrypto_data_dir/certificate_ec_prime256v1_orig.pem"
jcrypto_priv_key="$jcrypto_data_dir/private_key_ec_prime256v1_orig.pem"
jcrypto_in_file="$jcrypto_this_dir/in-cms-data.txt"
jcrypto_out_sig_file="$jcrypto_this_dir/out-cms-signed-ec.pem"
jcrypto_out_verify_file_from_jcrypto="$jcrypto_this_dir/out-cms-signed-ec-verify-jc.txt"
jcrypto_out_verify_file_from_ossl="$jcrypto_this_dir/out-cms-signed-ec-verify-ossl.txt"
jcrypto_out_ossl_sig_file="$jcrypto_this_dir/out-cms-signed-ec-ossl.pem"
jcrypto_out_ossl_verify_file_from_jcrypto="$jcrypto_this_dir/out-cms-signed-ec-ossl-verify-jc.txt"
jcrypto_out_ossl_verify_file_from_ossl="$jcrypto_this_dir/out-cms-signed-ec-ossl-verify-ossl.txt"

echo "JCRYPTO SIGN"
jcrypto cms sign -i "$jcrypto_in_file" -f PEM \
	    --signer-cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" -o "$jcrypto_out_sig_file"
jcrypto_dump_pem "$jcrypto_out_sig_file"

echo "OPENSSL SIGN"
# -nodetach embeds the content so the structure matches jcrypto's encapsulated default.
jcrypto_openssl cms -sign -binary -nodetach -in "$jcrypto_in_file" -outform PEM \
  -signer "$jcrypto_cert_file" -inkey "$jcrypto_priv_key" -out "$jcrypto_out_ossl_sig_file"
jcrypto_dump_pem "$jcrypto_out_ossl_sig_file"

# The signer certificate is embedded, so verification only needs to check the signature
# (-noverify), matching how jcrypto verifies without a trust chain.
echo "OPENSSL VERIFY OF OPENSSL"
jcrypto_openssl cms -verify -in "$jcrypto_out_ossl_sig_file" -inform PEM -noverify \
  -out "$jcrypto_out_ossl_verify_file_from_ossl"
jcrypto_cat "$jcrypto_out_ossl_verify_file_from_ossl"

echo "OPENSSL VERIFY OF JCRYPTO"
jcrypto_openssl cms -verify -in "$jcrypto_out_sig_file" -inform PEM -noverify \
  -out "$jcrypto_out_ossl_verify_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_ossl_verify_file_from_jcrypto"

echo "JCRYPTO VERIFY OF JCRYPTO"
jcrypto cms verify -i "$jcrypto_out_sig_file" -f PEM -o "$jcrypto_out_verify_file_from_jcrypto"
jcrypto_cat "$jcrypto_out_verify_file_from_jcrypto"

echo "JCRYPTO VERIFY OF OPENSSL"
jcrypto cms verify -i "$jcrypto_out_ossl_sig_file" -f PEM -o "$jcrypto_out_verify_file_from_ossl"
jcrypto_cat "$jcrypto_out_verify_file_from_ossl"

rm $jcrypto_out_sig_file $jcrypto_out_verify_file_from_jcrypto $jcrypto_out_verify_file_from_ossl
rm $jcrypto_out_ossl_sig_file $jcrypto_out_ossl_verify_file_from_jcrypto $jcrypto_out_ossl_verify_file_from_ossl
