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

jcrypto_nginx_setup "$jcrypto_nginx_type" 4443 8089

exec nginx -c "$jcrypto_nginx_conf"