#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_curve_name=$1
if [ -z "$jcrypto_curve_name" ]; then
  jcrypto_curve_name="prime256v1"
fi
jcrypto_orig_cert_file="$jcrypto_data_dir/certificate_ec_${jcrypto_curve_name}_orig.pem"
jcrypto_orig_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_orig.pem"
jcrypto_recip_cert_file="$jcrypto_data_dir/certificate_ec_${jcrypto_curve_name}_recip.pem"
jcrypto_recip_priv_key="$jcrypto_data_dir/private_key_ec_${jcrypto_curve_name}_recip.pem"

jcrypto_out_enc_file="$jcrypto_this_dir/out-smime-env-key-agree-stream-enc.txt"
jcrypto_out_plain_file="$jcrypto_this_dir/out-smime-env-key-agree-stream-plain.txt"

jcrypto mail encrypt -i "$jcrypto_this_dir/in-message-body.txt" -c aes-128-cbc --stream \
  --from 'Jakub<jakub@bukka.eu>' --to 'Lucas<lucas@bukka.eu>' --subject 'Test' \
  --recipient-cert "$jcrypto_recip_cert_file" --sender-cert "$jcrypto_orig_cert_file" \
  --private-key "$jcrypto_orig_priv_key" -o "$jcrypto_out_enc_file"
jcrypto_dump_smime "$jcrypto_out_enc_file"

jcrypto mail decrypt -i "$jcrypto_out_enc_file" -c aes-256-cbc  \
  --recipient-cert "$jcrypto_recip_cert_file" --sender-cert "$jcrypto_orig_cert_file" \
  --private-key "$jcrypto_recip_priv_key" -o "$jcrypto_out_plain_file"
jcrypto_cat "$jcrypto_out_plain_file"

rm "$jcrypto_out_enc_file" "$jcrypto_out_plain_file"
