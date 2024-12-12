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

jcrypto_pkcs11_proxy_protocol=tcp
if [[ "$JCRYPTO_PKCS11_PROXY" == "tls" ]]; then
  jcrypto_pkcs11_proxy_protocol="tls"
  jcrypto_pkcs11_proxy_psk_file="$jcrypto_tmp_dir/pkcs11-proxy-psk.txt"
fi
jcrypto_pkcs11_proxy_socket="$jcrypto_pkcs11_proxy_protocol://127.0.0.1:2346"

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

function jcrypto_info {
  echo "JCRYPTO CMD: $jcrypto_cmd"
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

function jcrypto_pkcs11_softhsm2_init_token {
  # Initialize the token
  softhsm2-util --init-token --slot 0 --label "jCryptoTestToken" --so-pin 1234 --pin 1234 || {
    echo "Error: Failed to initialize token."
    exit 1
  }
}

function jcrypto_pkcs11_softhsm2_setup {
  if [ -z "$jcrypto_pkcs11_prefix" ]; then
    if [ -z "$1" ]; then
      echo "Error: No prefix for SoftHSM2 setup."
      exit 1
    fi
    jcrypto_pkcs11_prefix="$jcrypto_tmp_dir/$1"
  fi

  if [[ "$jcrypto_pkcs11_softhsm2_tokens" != "$jcrypto_pkcs11_prefix-tokens" ]]; then
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

    jcrypto_pkcs11_softhsm2_library=$(jcrypto_find_first_existing_path jcrypto_pkcs11_softhsm2_default_paths)
    if [ $? -ne 0 ]; then
      echo "Error: PKCS#11 module not found in default paths."
      echo "Please install SoftHSM2 or specify the module path."
      exit 1
    fi
    jcrypto_pkcs11_library="$jcrypto_pkcs11_softhsm2_library"
    echo "Using PKCS11_LIBARY=$jcrypto_pkcs11_library"

    if [ -z "$jcrypto_pkcs11_tokens_keep" ]; then
      # Reset tokens
      if [ -d "$jcrypto_pkcs11_softhsm2_tokens" ]; then
        rm -rf "$jcrypto_pkcs11_softhsm2_tokens"
      fi
      mkdir "$jcrypto_pkcs11_softhsm2_tokens"
      jcrypto_pkcs11_softhsm2_init_token
    elif [ ! -d "$jcrypto_pkcs11_softhsm2_tokens" ]; then
      # Create tokens dir only if it does not exist
      mkdir "$jcrypto_pkcs11_softhsm2_tokens"
      jcrypto_pkcs11_softhsm2_init_token
    fi
  fi
}

function jcrypto_pkcs11_proxy_conf_setup {
  if [ -n "$JCRYPTO_PKCS11_PROXY_CONF" ]; then
    jcrypto_pkcs11_proxy_conf_in="$jcrypto_conf_dir/pkcs11-proxy-$JCRYPTO_PKCS11_PROXY_CONF.conf.in"
    if [ -f "$jcrypto_pkcs11_proxy_conf_in" ]; then
      jcrypto_pkcs11_proxy_conf="$jcrypto_tmp_dir/pkcs11-proxy-$JCRYPTO_PKCS11_PROXY_CONF.conf"
      cp "$jcrypto_pkcs11_proxy_conf_in" "$jcrypto_pkcs11_proxy_conf"
      export PKCS11_PROXY_CONF_FILE="$jcrypto_pkcs11_proxy_conf"
      echo "Using PKCS11_PROXY_CONF_FILE=$jcrypto_pkcs11_proxy_conf"
    else
      echo "Error: PKCS#11 proxy conf $jcrypto_pkcs11_proxy_conf_in not found."
      exit 1
    fi
  fi
}

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
  echo "Using PKCS11_PROXY_SOCKET=$jcrypto_pkcs11_proxy_socket"
  if [[ $jcrypto_pkcs11_proxy_protocol == "tls" ]]; then
    export PKCS11_PROXY_TLS_PSK_FILE="$jcrypto_pkcs11_proxy_psk_file"
    echo "Using PKCS11_PROXY_TLS_PSK_FILE=$jcrypto_pkcs11_proxy_psk_file"
  fi

  jcrypto_pkcs11_proxy_conf_setup
}

function jcrypto_pkcs11_proxy_daemon_setup {
  jcrypto_pkcs11_prefix="$jcrypto_tmp_dir/$1"
  jcrypto_pkcs11_softhsm2_setup "$@"
  jcrypto_pkcs11_proxy_conf_setup
  if [[ $jcrypto_pkcs11_proxy_protocol == "tls" ]]; then
    if [ ! -f "$jcrypto_pkcs11_proxy_psk_file" ]; then
      echo "client:$(head -c 32 /dev/urandom | xxd -p -c 64)" > "$jcrypto_pkcs11_proxy_psk_file"
    fi
    export PKCS11_PROXY_TLS_PSK_FILE="$jcrypto_pkcs11_proxy_psk_file"
    echo "Using PKCS11_PROXY_TLS_PSK_FILE=$jcrypto_pkcs11_proxy_psk_file"
  fi
  export PKCS11_DAEMON_SOCKET=$jcrypto_pkcs11_proxy_socket
  echo "Using PKCS11_DAEMON_SOCKET=$jcrypto_pkcs11_proxy_socket"
}

function jcrypto_pkcs11_setup {
  if [ -z "$1" ]; then
    echo "Error: PKCS#11 test name not set."
    exit 1
  fi
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

function jcrypto_openssl_pkcs11_engine_cnf_setup {
  jcrypto_openssl_cnf="$jcrypto_tmp_dir/openssl-$jcrypto_nginx_type.cnf"

  jcrypto_pkcs11_proxy_default_paths=(
    "/usr/local/ssl33/lib64/engines-3/pkcs11.so" # not exactly generic but my personal preference
    "/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so"
    "/usr/lib/engines-3/pkcs11.so"
    "/usr/lib/ssl/engines/libpkcs11.so"
    "/usr/lib/engines/engine_pkcs11.so"
  )
  jcrypto_libp11_path=$(jcrypto_find_first_existing_path jcrypto_pkcs11_proxy_default_paths)
  if [ $? -ne 0 ]; then
    echo "Error: libp11 engine not found in default paths."
    echo "Please install libp11 or specify the module path."
    exit 1
  fi
  sed "s|__MODULE_PATH__|$jcrypto_pkcs11_library|g" "$jcrypto_conf_dir/openssl-pkcs11-engine.cnf.in" > "$jcrypto_openssl_cnf"
  sed -i "s|__ENGINE_PATH__|$jcrypto_libp11_path|g" "$jcrypto_openssl_cnf"
  export OPENSSL_CONF="$jcrypto_openssl_cnf"
  echo "Using OPENSSL_CONF=$jcrypto_openssl_cnf"
}

function jcrypto_nginx_conf_setup {
  jcrypto_nginx_conf="$jcrypto_tmp_dir/nginx-$jcrypto_nginx_type.conf"
  jcrypto_nginx_client_body_temp_path="$jcrypto_tmp_dir/nginx/client_body_temp"
  jcrypto_nginx_proxy_temp_path="$jcrypto_tmp_dir/nginx/proxy_temp"

  if [ ! -d "$jcrypto_nginx_client_body_temp_path" ]; then
    mkdir -p "$jcrypto_nginx_client_body_temp_path"
  fi
  if [ ! -d "$jcrypto_nginx_proxy_temp_path" ]; then
    mkdir -p "$jcrypto_nginx_proxy_temp_path"
  fi

  sed "s|__SSL_CERT__|$jcrypto_nginx_ssl_cert|g" "$jcrypto_conf_dir/nginx.conf.in" > "$jcrypto_nginx_conf"
  sed -i "s|__SSL_KEY__|$jcrypto_nginx_ssl_key|g" "$jcrypto_nginx_conf"
  sed -i "s|__LISTEN_PORT__|$jcrypto_nginx_listen_port|g" "$jcrypto_nginx_conf"
  sed -i "s|__PROXY_PORT__|$jcrypto_nginx_proxy_port|g" "$jcrypto_nginx_conf"
  sed -i "s|__PID_FILE__|$jcrypto_tmp_dir/nginx-$jcrypto_nginx_type.pid|g" "$jcrypto_nginx_conf"
  sed -i "s|__CLIENT_BODY_TEMP_PATH__|$jcrypto_nginx_client_body_temp_path|g" "$jcrypto_nginx_conf"
  sed -i "s|__PROXY_TEMP_PATH__|$jcrypto_nginx_proxy_temp_path|g" "$jcrypto_nginx_conf"
}

function jcrypto_nginx_setup {
  jcrypto_nginx_type=$1
  jcrypto_nginx_test_name=$2
  jcrypto_nginx_cert_path=$3
  jcrypto_nginx_priv_key_alias=$4
  jcrypto_nginx_listen_port=$5
  jcrypto_nginx_proxy_port=$6

  if [[ $jcrypto_nginx_type == "pkcs11-engine" ]]; then
    jcrypto_pkcs11_setup $jcrypto_nginx_test_name
    jcrypto_openssl_pkcs11_engine_cnf_setup
    jcrypto_nginx_ssl_cert="$jcrypto_nginx_cert_path"
    jcrypto_nginx_ssl_key='"engine:pkcs11:pkcs11:token=jCryptoTestToken;object='$jcrypto_nginx_priv_key_alias'?pin-value=1234"'
  else
    jcrypto_nginx_ssl_cert="$jcrypto_data_dir/nginx_cert_ec_secp256r1.pem"
    jcrypto_nginx_ssl_key="$jcrypto_data_dir/nginx_private_key_ec_secp256r1.pem"
  fi
  jcrypto_nginx_conf_setup
}

function jcrypto_clean_tmp {
  rm -rf "$jcrypto_tmp_dir"
}