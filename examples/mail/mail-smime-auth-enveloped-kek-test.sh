#!/bin/bash

jcrypto_this_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$( dirname $jcrypto_this_dir )/common.sh"

jcrypto_out_enc_file="$jcrypto_this_dir/out-smime-auth-env-kek.p7m"
jcrypto mail encrypt -i "$jcrypto_this_dir/in-message-body.txt" -c aes-128-gcm \
      --from 'Jakub<jakub@bukka.eu>' --to 'Lucas<lucas@bukka.eu>' --subject 'Test' \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_enc_file"

# dump the content of the file (use openssl)
cat "$jcrypto_out_enc_file"
echo ""

jcrypto_out_plain_file="$jcrypto_this_dir/out-smime-auth-env-kek-plain.txt"
jcrypto mail decrypt -i "$jcrypto_out_enc_file" -c aes-128-gcm \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
      -o "$jcrypto_out_plain_file"

cat "$jcrypto_out_plain_file"
echo ""

rm "$jcrypto_out_enc_file" "$jcrypto_out_plain_file"
