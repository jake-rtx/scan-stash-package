#!/bin/bash

# This should fail with no response, since the user can't do this.

echo -n "john|dumpsessions" | nc -N 127.0.0.1 10088
echo ""
