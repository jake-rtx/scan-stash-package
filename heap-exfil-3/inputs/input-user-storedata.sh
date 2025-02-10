#!/bin/bash

echo -n "john|storedata|24|This-is-plain-user-data." | nc -N 127.0.0.1 10088
echo ""
