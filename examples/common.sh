#!/bin/bash

set -e

# set base directory
if readlink ${BASH_SOURCE[0]} > /dev/null; then
  jcrypto_root="$( dirname "$( dirname "$( readlink ${BASH_SOURCE[0]} )" )" )"
else
  jcrypto_root="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"
fi
jcrypto_conf_dir="$jcrypto_root/examples/conf"
jcrypto_data_dir="$jcrypto_root/examples/data"
jcrypto_tmp_dir="$jcrypto_root/examples/tmp"

if [ ! -d "$jcrypto_tmp_dir" ]; then
  mkdir "$jcrypto_tmp_dir"
fi

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

# Cat file, base64 encode it and print new line
function jcrypto_cat_b64 {
  cat $1 | base64
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

function jcrypto_find_first_existing_path {
  local -n paths=$1
  for path in "${paths[@]}"; do
    if [ -f "$path" ]; then
      echo "$path"
      return 0
    fi
  done
  return 1
}

function jcrypto_pkcs11_make_java_config {
  jcrypto_pkcs11_name=$1
  jcrypto_pkcs11_library="$2"
  jcrypto_pkcs11_java_config="$jcrypto_pkcs11_prefix-pkcs11.cfg"

  # Create config for SunPKCS11 Java provider
  sed "s|__PKCS11_LIBRARY__|$jcrypto_pkcs11_library|g" "$jcrypto_conf_dir/pkcs11.cfg.in" > "$jcrypto_pkcs11_java_config"
  sed -i "s|__PKCS11_NAME__|$jcrypto_pkcs11_name|g" "$jcrypto_pkcs11_java_config"
}

function jcrypto_pkcs11_softhsm2_setup {
  if [ -z "$1" ]; then
    echo "Error: PKCS#11 test name not set."
    exit 1
  fi
  jcrypto_pkcs11_softhsm2_tokens="$jcrypto_pkcs11_prefix-tokens"
  jcrypto_pkcs11_softhsm2_config="$jcrypto_pkcs11_prefix-softhsm2.conf"

  # Create and set SoftHSM2 config
  sed "s|__TOKENS_DIR__|$jcrypto_pkcs11_softhsm2_tokens|g" "$jcrypto_conf_dir/softhsm2.conf.in" > "$jcrypto_pkcs11_softhsm2_config"
  export SOFTHSM2_CONF="$jcrypto_pkcs11_softhsm2_config"
  echo "Using SOFTHSM2_CONF=$jcrypto_pkcs11_softhsm2_config"

  # Find and check PKCS#11 name and library
  jcrypto_pkcs11_name=SoftHSM2
  echo "Using PKCS11_NAME=$jcrypto_pkcs11_name"
  jcrypto_pkcs11_softhsm2_default_paths=(
      "/usr/local/lib/softhsm/libsofthsm2.so"
      "/usr/lib/softhsm/libsofthsm2.so"
  )

  jcrypto_pkcs11_library=$(jcrypto_find_first_existing_path jcrypto_pkcs11_softhsm2_default_paths)
  if [ $? -ne 0 ]; then
      echo "Error: PKCS#11 module not found in default paths."
      echo "Please install SoftHSM2 or specify the module path."
      exit 1
  fi
  echo "Using PKCS11_LIBARY=$jcrypto_pkcs11_library"

  if [ -d "$jcrypto_pkcs11_softhsm2_tokens" ]; then
    rm -rf "$jcrypto_pkcs11_softhsm2_tokens"
  fi
  mkdir "$jcrypto_pkcs11_softhsm2_tokens"

  # Initialize the token
  softhsm2-util --init-token --slot 0 --label "jCryptoTestToken" --so-pin 1234 --pin 1234 || {
      echo "Error: Failed to initialize token."
      exit 1
  }
}

jcrypto_pkcs11_proxy_socket="tcp://127.0.0.1:2346"

function jcrypto_pkcs11_proxy_client_setup {
  # Find and check PKCS#11 name and library
    jcrypto_pkcs11_name=PKCS11Proxy
    echo "Using PKCS11_NAME=$jcrypto_pkcs11_name"
    jcrypto_pkcs11_proxy_default_paths=(
        "/usr/local/lib/libpkcs11-proxy.so"
        "/lib/libpkcs11-proxy.so"
        "/usr/lib/libpkcs11-proxy.so"
    )
    jcrypto_pkcs11_library=$(jcrypto_find_first_existing_path jcrypto_pkcs11_proxy_default_paths)
    if [ $? -ne 0 ]; then
        echo "Error: PKCS#11 module not found in default paths."
        echo "Please install PKCS11-PROXY or specify the module path."
        exit 1
    fi
    echo "Using PKCS11_LIBARY=$jcrypto_pkcs11_library"

    export PKCS11_PROXY_SOCKET=$jcrypto_pkcs11_proxy_socket
}

function jcrypto_pkcs11_setup {
  jcrypto_pkcs11_test_name=$1
  jcrypto_pkcs11_prefix="$jcrypto_tmp_dir/$jcrypto_pkcs11_test_name"
  if [ -n "$JCRYPTO_PKCS11_PROXY" ]; then
    jcrypto_pkcs11_proxy_client_setup "$@"
  else
    jcrypto_pkcs11_softhsm2_setup "$@"
  fi

  jcrypto_pkcs11_make_java_config $jcrypto_pkcs11_name "$jcrypto_pkcs11_library"
}

function jcrypto_pkcs11_generate_key {
  key_type="$1"
  key_label="$2"

  pkcs11-tool --module "$jcrypto_pkcs11_library" --login --pin 1234 --keypairgen --key-type "$key_type" \
    --id 01 --label "$key_label" || {
      echo "Error: Failed to generate key pair."
      exit 1
  }
}

function jcrypto_clean_tmp {
  rm -rf "$jcrypto_tmp_dir"
}