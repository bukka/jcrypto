#!/bin/bash

# set base directory
if readlink ${BASH_SOURCE[0]} > /dev/null; then
  jcrypto_root="$( dirname "$( dirname "$( readlink ${BASH_SOURCE[0]} )" )" )"
else
  jcrypto_root="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"
fi

# this assumes that `mvn clean compile assembly:single` has been run first
jcrypto_cmd="java -cp $jcrypto_root/target/jcrypto-1.0-SNAPSHOT-jar-with-dependencies.jar eu.bukka.Main"

function jcrypto {
  echo $@
  $jcrypto_cmd $@
}

jcrypto cms encrypt -i examples/in-cms-data.txt -f PEM -c aes-128-gcm \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
        -o $jcrypto_root/examples/out-cms-kek.pem

# dump the content of the file (use openssl)
openssl asn1parse -i -in examples/out-cms-kek.pem

jcrypto cms decrypt -i $jcrypto_root/examples/out-cms-kek.pem -f PEM -c aes-128-gcm \
	    --secret-key=000102030405060708090A0B0C0D0E0F --secret-key-id=C0FEE0 \
        -o $jcrypto_root/examples/out-cms-plain.txt

cat $jcrypto_root/examples/out-cms-plain.txt
