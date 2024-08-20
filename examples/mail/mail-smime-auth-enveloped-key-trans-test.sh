#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_cert_file="$jcrypto_data_dir/certificate.pem"
jcrypto_priv_key="$jcrypto_data_dir/private_key.pem"

jcrypto_out_enc_file="$jcrypto_this_dir/out-smime-auth-env-key-trans-enc.txt"
jcrypto mail encrypt -i "$jcrypto_this_dir/in-message-body.txt" -c aes-256-gcm \
      --from 'Jakub<jakub@bukka.eu>' --to 'Lucas<lucas@bukka.eu>' --subject 'Test' \
	    --cert "$jcrypto_cert_file" -o "$jcrypto_out_enc_file"

jcrypto_dump_smime "$jcrypto_out_enc_file"

jcrypto_out_plain_file="$jcrypto_this_dir/out-smime-auth-env-key-trans-plain.txt"
jcrypto mail decrypt -i "$jcrypto_out_enc_file" -c aes-256-gcm \
	    --cert "$jcrypto_cert_file" --private-key "$jcrypto_priv_key" \
      -o "$jcrypto_out_plain_file"

cat "$jcrypto_out_plain_file"
echo ""

rm "$jcrypto_out_enc_file" "$jcrypto_out_plain_file"
