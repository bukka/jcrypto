#!/bin/bash

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
  echo $@
  $jcrypto_cmd $@
}