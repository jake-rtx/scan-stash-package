#!/bin/bash

echo "Normal traffic (9 sequential requests)"
./input-user.sh
./input-user.sh
./input-user.sh
./input-user.sh
./input-admin.sh
./input-admin.sh
./input-admin.sh
./input-admin.sh
./input-dumpsessions.sh

echo  "User-space heartbleed attack (see out.txt for read results)"
strace -fvs11000 --read=4 -e read -o out.txt ./input-heartbleed.sh
echo ""
