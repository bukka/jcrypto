#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_enc_file="$jcrypto_this_dir/out-smime-env-kek-stream-enc.txt"
jcrypto_out_plain_file="$jcrypto_this_dir/out-smime-env-kek-stream-plain.txt"

jcrypto mail encrypt -i "$jcrypto_this_dir/in-message-body.txt" -c aes-128-cbc --stream \
      --from 'Jakub<jakub@bukka.eu>' --to 'Lucas<lucas@bukka.eu>' --subject 'Test' \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_enc_file"

jcrypto_dump_smime "$jcrypto_out_enc_file"

jcrypto mail decrypt -i "$jcrypto_out_enc_file" -c aes-128-cbc --stream \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_plain_file"

jcrypto_cat "$jcrypto_out_plain_file"

rm "$jcrypto_out_enc_file" "$jcrypto_out_plain_file"
