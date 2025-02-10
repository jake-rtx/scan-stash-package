#!/usr/bin/env bash

# RUN THIS SCRIPT FIRST
# Script run by PRT to simulate a transaction user inputs to the server

thisdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd -P "$( dirname "$SOURCE" )" && pwd)"
he3dir=$thisdir/..

UDATA="This-is-plain-user-data."
data=""

loginfo() {
  echo "INFO: $*"
}

logerr() {
  echo "ERROR: $*"
  exit 1
}

check () {
  local op
  local expected
  local actual
  local failmsg

  op="$1"
  expected="$2"
  actual="$3"
  failmsg="${4:-check() failure: OP: $op, $expected, Actual: $actual}"

  case "$op" in
    "match" )
      if [ ! "$expected" = "$actual" ]; then
        logerr "$failmsg"
      fi
      ;;
    "nomatch" )
      if [ "$expected" = "$actual" ]; then
        logerr "$failmsg"
      fi
      ;;
  esac

  loginfo "Check passed: $actual"
}

# pass "public" or "private"
read_sa () {
  local devfile
  local bs
  local skip

  devfile="$1"
  bs="${2:-1024}"
  skip="${3:-0}"

  data=`dd if=/dev/struct-access/$devfile bs=$bs count=1 skip=$skip status=none iflag=fullblock,skip_bytes | tr -d '\0'`

  echo "$data"
}

# ##############################
# Clear struct-access files
# ##############################
loginfo "Resetting data in struct-access files..."

dd  if=/dev/zero \
    of=/dev/struct-access/public \
    bs=1024 \
    count=1 \
    seek=0 \
    status=none \
    oflag=seek_bytes

dd  if=/dev/zero \
    of=/dev/struct-access/private \
    bs=1024 \
    count=1 \
    seek=0 \
    status=none \
    oflag=seek_bytes

# ##############################
# Do some transactions as a "user" to the server.
# Store some data in the /dev/struct-access/public file
# ##############################
loginfo "Normal user traffic to server with user store."

loginfo "User access to root /tmp file expected to fail..."
text=`$thisdir/input-user.sh | tr -d '\0'`
check match "FAILURE" $text

loginfo "User store-data in struct-access public expected to succeed..."
text=`$thisdir/input-user-storedata.sh | tr -d '\0'`
check match "SUCCESS" $text

# ##############################
# Validate that input-user-storedata.sh actually stored the data into the
# /dev/struct-access/public file.
# ##############################
loginfo "Validate that the user stored data in the public file..."

data=`read_sa public`
check match "$UDATA" "$data" \
  "Expected to read stored user data, but didn't find it correctly!"

loginfo "Good. user stored data validated."

exit 0