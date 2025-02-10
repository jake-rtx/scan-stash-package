#!/bin/bash

echo -n "john|heartbleed|32768|x" | nc -N 127.0.0.1 10088
echo ""
