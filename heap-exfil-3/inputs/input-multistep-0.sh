#!/bin/bash

# This script runs as root.

UDATA="This-is-plain-user-data."
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
loginfo "Normal user traffic to server with user store and legal heartbeats."

loginfo "User access to root /tmp file expected to fail..."
text=`./input-user.sh | tr -d '\0'`
check match "FAILURE" $text

loginfo "Legal heartbeat..."
text=`./input-heartbleed-legal.sh | tr -d '\0'`
check match "x" $text

loginfo "User access to root /tmp file expected to fail..."
text=`./input-user.sh | tr -d '\0'`
check match "FAILURE" $text

loginfo "Legal heartbeat..."
text=`./input-heartbleed-legal.sh | tr -d '\0'`
check match "x" $text

loginfo "User store-data in struct-access public expected to succeed..."
text=`./input-user-storedata.sh | tr -d '\0'`
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

# ##############################
# Attempt userspace heartbleed, see that the admin hasn't stored secret yet.
# ##############################
loginfo "Attempt userspace heartbleed, notice there isn't an admin datastore..."

./input-heartbleed.sh | grep 'admin|storedata' > /dev/null 2>&1
check nomatch "$?" "0" \
  "Witnessed admin|storedata before the admin stored it!"
loginfo "Good. No admin data store in heartbleed."

# ##############################
# Now act as the "admin" user, do some operations, and store admin secret.
# ##############################
loginfo "Normal admin traffic with admin secret store."

loginfo "Root access to root /tmp file expected to succeed..."
text=`./input-admin.sh | tr -d '\0'`
check match "SUCCESS" "$text"

loginfo "Root access to root /tmp file expected to succeed..."
text=`./input-admin.sh | tr -d '\0'`
check match "SUCCESS" "$text"

loginfo "Root store-data in struct-access private expected to succeed..."
text=`./input-admin-storedata.sh | tr -d '\0'`
check match "SUCCESS" "$text"

loginfo "Dumping the operations performed in this session..."
text=`./input-dumpsessions.sh | tr -d '\0'`
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
# Attempt userspace heartbleed, we should see the admin|storedata now!
# ##############################
loginfo "Attempt userspace heartbleed, there should be an admin datastore op..."

# Attempt userspace heartbleed, see that the admin HAS stored the secret!
./input-heartbleed.sh | grep 'admin|storedata' > /dev/null 2>&1
check match "$?" "0" \
  "I should have seen admin|storedata--but I didn't!"
loginfo "Good. Heartbleed worked! We saw the admin data store op."

# ##############################
# Exfiltrate the admin secret with the vulcan neck pinch from the public
# /dev/struct-access/public file.
# ##############################
loginfo "Exfiltrate the admin data from the struct-access/public file."

data=""
data=`read_sa public 2048 1`
check match "$RDATA" "$data"

loginfo "Good. Exfiltration SUCCESSFUL: $data"

exit 0

