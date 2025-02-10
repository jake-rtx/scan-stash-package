#!/bin/bash

echo -n "john|heartbleed|1|x" | nc -N 127.0.0.1 10088
echo ""
