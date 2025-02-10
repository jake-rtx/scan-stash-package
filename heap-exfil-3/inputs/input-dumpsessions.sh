#!/bin/bash

echo -n "admin|dumpsessions" | nc -N 127.0.0.1 10088
echo ""