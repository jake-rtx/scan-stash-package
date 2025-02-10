#!/usr/bin/env bash

# RUN THIS SCRIPT SECOND
# Script run by PRT to simulate a transaction admin inputs to the server

thisdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd -P "$( dirname "$SOURCE" )" && pwd)"
he3dir=$thisdir/..

RDATA="deadbeef-53C237-deadbeef"
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
# Now act as the "admin" user, do some operations, and store admin secret.
# ##############################
loginfo "Normal admin traffic with admin secret store."

loginfo "Root access to root /tmp file expected to succeed..."
text=`$thisdir/input-admin.sh | tr -d '\0'`
check match "SUCCESS" "$text"

loginfo "Root store-data in struct-access private expected to succeed..."
text=`$thisdir/input-admin-storedata.sh | tr -d '\0'`
check match "SUCCESS" "$text"

loginfo "Dumping the operations performed in this session..."
text=`$thisdir/input-dumpsessions.sh | tr -d '\0'`
check nomatch "" "$text"

# ##############################
# Validate that input-admin-storedata.sh actually stored the data into the
# /dev/struct-access/private file.
# ##############################
loginfo "Validate that the admin stored data in the private file..."

data=`read_sa private`
check match "$RDATA" "$data" \
  "Expected to read stored admin data, but didn't find it correctly!"
loginfo "Good. Admin performed data store."

# ##############################
# Caldera now attempts to do heartbleed attack...
# ##############################

loginfo "PRT user and admin data added."

exit 0