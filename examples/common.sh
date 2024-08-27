#!/bin/bash

set -e

# set base directory
if readlink ${BASH_SOURCE[0]} > /dev/null; then
  jcrypto_root="$( dirname "$( dirname "$( readlink ${BASH_SOURCE[0]} )" )" )"
else
  jcrypto_root="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"
fi
jcrypto_data_dir="$jcrypto_root/examples/data"

# this assumes that `mvn clean compile assembly:single` has been run first
jcrypto_cmd="java -cp $jcrypto_root/target/jcrypto-1.0-SNAPSHOT-jar-with-dependencies.jar eu.bukka.jcrypto.Main"

function jcrypto {
  echo jcrypto $@
  $jcrypto_cmd $@
}

function jcrypto_openssl {
  echo openssl $@
  openssl $@
}

# Cat file and print new line
function jcrypto_cat {
  cat $1
  echo ""
}

function jcrypto_dump_pem {
  echo "=== ASN.1 ==="
  jcrypto_openssl asn1parse -i -in "$1"
}

function jcrypto_dump_smime {
  jcrypto_smime_file_txt="$1"
  jcrypto_smime_file_b64="$1.b64"
  sed '/^[^:]*: /d'  "$jcrypto_smime_file_txt" | sed '/^[[:space:]]*$/d' > "$jcrypto_smime_file_b64"

  echo "=== SMIME ==="
  cat "$jcrypto_smime_file_txt"
  echo ""
  echo "=== ASN.1 ==="
  jcrypto_openssl asn1parse -i -in "$jcrypto_smime_file_b64" -inform B64

  rm "$jcrypto_smime_file_b64"
}