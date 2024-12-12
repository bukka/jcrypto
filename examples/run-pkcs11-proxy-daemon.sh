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

if [ -n "$PKCS11_KEYS_REUSE" ]; then
  jcrypto_pkcs11_tokens_keep=1
fi

if [ -n "$1" ]; then
  pkcs11_daemon_test_name="$1"
else
  pkcs11_daemon_test_name=pkey-pkcs11-proxy-daemon
fi


jcrypto_pkcs11_proxy_daemon_setup "$pkcs11_daemon_test_name"

exec pkcs11-daemon "$jcrypto_pkcs11_library"