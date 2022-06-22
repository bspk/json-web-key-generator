#!/bin/sh

BASEDIR=$(dirname $(readlink -f "$0"))

java -jar "${BASEDIR}/target/json-web-key-generator.jar" "$@"
