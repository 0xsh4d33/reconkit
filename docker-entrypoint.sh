#!/bin/sh
set -e
exec reconkit "$@" -config /etc/reconkit/config.yaml
