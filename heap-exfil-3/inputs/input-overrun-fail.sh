#!/bin/bash

echo -n "foo|overrun|14|/proc/slabinfo" | nc -N 127.0.0.1 10088
echo ""
