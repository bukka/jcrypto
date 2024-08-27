#!/bin/bash

jc_data_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
jc_data_dir="${jc_data_dir}/data"

if [ -z "$1" ]; then
  echo "Missing algorithm"
  exit 1
fi
jc_alg="$1"

function jc_openssl() {
  echo openssl $@
  openssl $@
}

function jc_create_rsa() {
  jc_rsa_size=$1
  jc_alg_name="rsa_$jc_rsa_size"
  jc_private_key="${jc_data_dir}/private_key_${jc_alg_name}.pem"
  jc_certificate="${jc_data_dir}/certificate_${jc_alg_name}.pem"
  jc_openssl genpkey -algorithm RSA -out "$jc_private_key" -pkeyopt rsa_keygen_bits:$jc_rsa_size
  jc_openssl req -new -x509 -key "$jc_private_key" -out "$jc_certificate" -days 1825 \
    -subj "/C=UK/ST=England/L=London/O=Zelenka/CN=Jakub"
}

function jc_create_dh() {
  jc_dh_size=$1
  jc_alg_name="dh_${jc_dh_size}"
  jc_private_key="${jc_data_dir}/private_key_${jc_alg_name}.pem"
  jc_public_key="${jc_data_dir}/public_key_${jc_alg_name}.pem"
  jc_dh_param="${jc_data_dir}/dhparam_${jc_dh_size}.pem"

  # for DH we generate only public private key pair
  jc_openssl dhparam -out "$jc_dh_param" ${jc_dh_size}
  jc_openssl genpkey -paramfile "$jc_dh_param" -out "$jc_private_key"
  jc_openssl pkey -in "$jc_private_key" -pubout -out "$jc_public_key"
}

function jc_create_ec() {
    jc_ec_name=$1
    jc_ec_type=$2
    jc_alg_name="ec_${jc_ec_name}"
    jc_private_key="${jc_data_dir}/private_key_${jc_alg_name}_${jc_ec_type}.pem"
    jc_certificate="${jc_data_dir}/certificate_${jc_alg_name}_${jc_ec_type}.pem"
    jc_openssl ecparam -genkey -name $jc_ec_name -out "$jc_private_key"
    jc_openssl req -new -x509 -key "$jc_private_key" -out "$jc_certificate" -days 1825 \
          -subj "/C=UK/ST=England/L=London/O=Zelenka/CN=$jc_ec_type"
}

case "$jc_alg" in
  rsa)
    jc_create_rsa 2048
    ;;
  dh)
    jc_create_dh 2048 orig
    jc_create_dh 2048 recip
    ;;
  ec)
    jc_create_ec brainpoolP256r1 orig
    jc_create_ec brainpoolP256r1 recip
    jc_create_ec prime256v1 orig
    jc_create_ec prime256v1 recip
    ;;
  *)
    echo "Unknown algorithm"
    exit 1
    ;;
esac
