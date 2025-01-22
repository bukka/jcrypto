#!/bin/bash

set -e

# set base directory
if readlink ${BASH_SOURCE[0]} > /dev/null; then
  jcrypto_root="$( dirname "$( dirname "$( readlink ${BASH_SOURCE[0]} )" )" )"
else
  jcrypto_root="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"
fi
jcrypto_this_dir="$jcrypto_root/examples"

source "$jcrypto_this_dir/common.sh"

if [ -n "$1" ]; then
  jcrypto_nginx_type="$1";
else
  jcrypto_nginx_type="basic";
fi

if [ -n "$2" ]; then
  jcrypto_nginx_test_name="$2"
else
  jcrypto_pkcs11_tokens_keep=1
  jcrypto_nginx_test_name=pkey-server
fi

if [ -n "$3" ]; then
  jcrypto_nginx_cert_path="$3"
else
  jcrypto_nginx_cert_path="$jcrypto_tmp_dir/nginx-cert-$jcrypto_nginx_type.pem"
fi

if [ -n "$4" ]; then
  jcrypto_nginx_key_alias="$4"
else
  jcrypto_nginx_key_alias=JavaTestNginxECKey
  if [[ "$jcrypto_nginx_type" == "pkcs11-engine" || "$jcrypto_nginx_type" == "pkcs11-provider" ]]; then
    jcrypto_create_cert=1
  fi
fi

jcrypto_nginx_client_cert_path="$jcrypto_data_dir/nginx_ca_cert_ec_secp256r1.pem"

jcrypto_nginx_setup "$jcrypto_nginx_type" "$jcrypto_nginx_test_name" "$jcrypto_nginx_cert_path" \
  "$jcrypto_nginx_key_alias" 4443 8089 "$jcrypto_nginx_client_cert_path"

if [ -n "$jcrypto_create_cert" ]; then
  jcrypto_curve_name=$5
  if [ -z "$jcrypto_curve_name" ]; then
    jcrypto_curve_name="prime256v1"
  fi
  jcrypto_pkcs11_softhsm2_setup $jcrypto_nginx_test_name

  jcrypto_key_pin=5678
  jcrypto_key_token_name=jCryptoTestKeyToken
  jcrypto_key_slot_id=$(pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --list-slots \
    | grep -B 1 $jcrypto_key_token_name | grep "Slot" | cut -d' ' -f7)
  echo "JCRYPTO PKCS11 SLOT: $jcrypto_key_slot_id"
  jcrypto_key_found=$(pkcs11-tool --module "$jcrypto_pkcs11_softhsm2_library" --login --slot $jcrypto_key_slot_id \
    --pin $jcrypto_key_pin --list-objects 2> /dev/null | grep -q "label: .*${jcrypto_nginx_key_alias}"; echo $?)
  if [ "$jcrypto_key_found" -ne 0 -o ! -f "$jcrypto_nginx_cert_path" ]; then
    echo "JCRYPTO NGINX KEY CREATION"
    rm -f "$jcrypto_nginx_cert_path"
    if [ "$jcrypto_key_found" -ne 0 ]; then
      pkcs11-tool --module "$jcrypto_pkcs11_softhsm2_library" --login --slot $jcrypto_key_slot_id --pin $jcrypto_key_pin \
        --keypairgen --key-type EC:$jcrypto_curve_name --id 01 --label "$jcrypto_nginx_key_alias"
    fi
    if [[ "$jcrypto_nginx_type" == "pkcs11-engine" ]]; then
      openssl x509 -engine pkcs11 -new -days 365 \
        -signkey "pkcs11:token=$jcrypto_key_token_name;object=$jcrypto_nginx_key_alias;type=private?pin-value=$jcrypto_key_pin" \
        -keyform engine -out "$jcrypto_nginx_cert_path" -subj "/CN=Self-Signed"
    else # pkcs11-provider
      if [ -n "$JCRYPTO_PKCS11_PROXY" ]; then
        jcrypto_openssl_pkcs11_provider_cnf_setup softhsm2
      fi
      openssl x509 -new -days 365 -propquery "provider=pkcs11" \
        -signkey "pkcs11:token=$jcrypto_key_token_name;object=$jcrypto_nginx_key_alias;type=private?pin-value=$jcrypto_key_pin" \
        -out "$jcrypto_nginx_cert_path" -subj "/CN=Self-Signed"
      if [ -n "$JCRYPTO_PKCS11_PROXY" ]; then
        jcrypto_openssl_pkcs11_provider_cnf_setup proxy
      fi
    fi
  fi
fi

echo "JCRYPTO NGINX START: nginx -c "$jcrypto_nginx_conf""
exec nginx -c "$jcrypto_nginx_conf"
