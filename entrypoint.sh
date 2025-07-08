#!/bin/bash

if [ ! -e /dev/i2c-1 ]; then
  echo "I2C device not found!"
  exit 1
fi

flask db upgrade

exec "$@"