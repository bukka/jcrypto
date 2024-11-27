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

jcrypto_pkcs11_proxy_daemon_setup

exec pkcs11-daemon "$jcrypto_pkcs11_library"