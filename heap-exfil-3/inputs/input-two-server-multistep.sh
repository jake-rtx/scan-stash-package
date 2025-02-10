#!/usr/bin/env bash

# Server one using regular SA with user "john"
# Server two using SA-split with user "james"

thisdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd -P "$( dirname "$SOURCE" )" && pwd)"
he3dir=$thisdir/..


SA_UDATA="This-is-plain-user-data."
SAS_UDATA="Thes-es-plaen-usir-data."
SA_RDATA="deaddead-53C237-deaddead"
SAS_RDATA="beefbeef-53C237-beefbeef"
data=""

PORT_ONE="10088"
PORT_TWO="10090"

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
read_sa() {
  local devfile
  local bs
  local skip

  devfile="$1"
  bs="${2:-1024}"
  skip="${3:-0}"

  data=`dd if=/dev/struct-access/$devfile bs=$bs count=1 skip=$skip status=none iflag=fullblock,skip_bytes | tr -d '\0'`

  echo "$data"
}

# pass "public" or "private"
read_sa_split() {
  local devfile
  local bs
  local skip

  devfile="$1"
  bs="${2:-1024}"
  skip="${3:-0}"

  data=`dd if=/dev/struct-access-split/$devfile bs=$bs count=1 skip=$skip status=none iflag=fullblock,skip_bytes | tr -d '\0'`

  echo "$data"
}

# ##############################
# TODO Populate
# ##############################
input_user() {
  port="$1"
  echo -n "john|openfile" | nc -N 127.0.0.1 $port
  echo ""
}

input_user_storedata() {
  port="$1"
  echo -n "john|storedata|24|This-is-plain-user-data." | nc -N 127.0.0.1 $port
  echo ""
}


input_user_two() {
  port="$1"
  echo -n "james|openfile" | nc -N 127.0.0.1 $port
  echo ""
}

input_user_storedata_two() {
  port="$1"
  echo -n "james|storedata|24|Thes-es-plaen-usir-data." | nc -N 127.0.0.1 $port
  echo ""
}

input_admin() {
  port="$1"
  echo -n "admin|openfile" | nc -N 127.0.0.1 $port
  echo ""
}

input_admin_storedata() {
  port="$1"
  echo -n "admin|storedata|24|deaddead-53C237-deaddead" | nc -N 127.0.0.1 $port
  echo ""
}

input_admin_storedata_two() {
  port="$1"
  echo -n "admin|storedata|24|beefbeef-53C237-beefbeef" | nc -N 127.0.0.1 $port
  echo ""
}

input_dumpsessions() {
  port="$1"
  echo -n "admin|dumpsessions" | nc -N 127.0.0.1 $port
  echo ""
}

input_heartbleed_legal() {
  port="$1"
  echo -n "john|heartbleed|1|x" | nc -N 127.0.0.1 $port
  echo ""
}

input_heartbleed() {
  port="$1"
  echo -n "john|heartbleed|32768|x" | nc -N 127.0.0.1 $port
  echo ""
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
# Clear struct-access-split files
# ##############################
loginfo "Resetting data in struct-access files..."

dd  if=/dev/zero \
    of=/dev/struct-access-split/public \
    bs=1024 \
    count=1 \
    seek=0 \
    status=none \
    oflag=seek_bytes

dd  if=/dev/zero \
    of=/dev/struct-access-split/private \
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

loginfo "Server One: User access to root /tmp file expected to fail..."
one=$(input_user $PORT_ONE | tr -d '\0')
echo "one: $one"
check match "FAILURE" $one

loginfo "Server One: Legal heartbeat..."
one=$(input_heartbleed_legal $PORT_ONE | tr -d '\0')
check match "x" $one

loginfo "Server One: User store-data in struct-access public expected to succeed..."
one=$(input_user_storedata $PORT_ONE | tr -d '\0')
check match "SUCCESS" $one

# ##############################
# Validate that input-user-storedata.sh actually stored the data into the
# /dev/struct-access/public file.
# ##############################
loginfo "Struct-Access: Validate that the user stored data in the public file..."

data=`read_sa public`
check match "$SA_UDATA" "$data" \
  "Expected to read stored user data, but didn't find it correctly!"

loginfo "Good. user stored data validated."

# ##############################
# Do some transactions as a "user" to the server.
# Store some data in the /dev/struct-access-split/public file
# ##############################

loginfo "Server Two: User access to root /tmp file expected to fail..."
two=$(input_user_two $PORT_TWO | tr -d '\0')
check match "FAILURE" $two

loginfo "Server Two: User store-data in struct-access public expected to succeed..."
two=$(input_user_storedata_two $PORT_TWO | tr -d '\0')
check match "SUCCESS" $two

loginfo "Server Two: Legal heartbeat..."
two=$(input_heartbleed_legal $PORT_TWO | tr -d '\0')
check match "x" $two

# ##############################
# Validate that input-user-storedata.sh actually stored the data into the
# /dev/struct-access-split/public file.
# ##############################
loginfo "Struct-Access-Split: Validate that the user stored data in the public file..."

data=`read_sa_split public`
check match "$SAS_UDATA" "$data" \
  "Expected to read stored user data, but didn't find it correctly!"

loginfo "Good. user stored data validated."

# ##############################
# Attempt userspace heartbleed, see that the admin hasn't stored secret yet.
# ##############################
loginfo "Server One: Attempt userspace heartbleed, notice there isn't an admin datastore..."

input_heartbleed $PORT_ONE | grep 'admin|storedata' > /dev/null 2>&1
check nomatch "$?" "0" \
  "Witnessed admin|storedata before the admin stored it!"
loginfo "Server One: Good. No admin data store in heartbleed."

# ##############################
# Attempt userspace heartbleed, see that the admin hasn't stored secret yet.
# ##############################
loginfo "Server Two: Attempt userspace heartbleed, notice there isn't an admin datastore..."

input_heartbleed $PORT_TWO | grep 'admin|storedata' > /dev/null 2>&1
check nomatch "$?" "0" \
  "Witnessed admin|storedata before the admin stored it!"
loginfo "Server Two: Good. No admin data store in heartbleed."

# ##############################
# Now act as the "admin" user, do some operations, and store admin secret.
# ##############################
loginfo "Normal admin traffic with admin secret store."

loginfo "Server One: Root access to root /tmp file expected to succeed..."
one=$(input_admin $PORT_ONE | tr -d '\0')
check match "SUCCESS" "$one"

loginfo "Server One: Root store-data in struct-access private expected to succeed..."
one=$(input_admin_storedata $PORT_ONE | tr -d '\0')
check match "SUCCESS" "$one"

loginfo "Server One: Dumping the operations performed in this session..."
one=$(input_dumpsessions $PORT_ONE | tr -d '\0')
check nomatch "" "$one"

loginfo "Server Two: Root access to root /tmp file expected to succeed..."
two=$(input_admin $PORT_TWO | tr -d '\0')
check match "SUCCESS" "$two"

loginfo "Server Tw0: Root store-data in struct-access private expected to succeed..."
two=$(input_admin_storedata_two $PORT_TWO | tr -d '\0')
check match "SUCCESS" "$two"

loginfo "Server Two: Dumping the operations performed in this session..."
two=$(input_dumpsessions $PORT_TWO | tr -d '\0')
check nomatch "" "$two"

# ##############################
# Validate that input-admin-storedata.sh actually stored the data into the
# /dev/struct-access/private file.
# ##############################
loginfo "Struct-Access: Validate that the admin stored data in the private file..."

data=`read_sa private`
check match "$SA_RDATA" "$data" \
  "Expected to read stored admin data, but didn't find it correctly!"
loginfo "Good. Admin performed data store."


# ##############################
# Validate that input-admin-storedata.sh actually stored the data into the
# /dev/struct-access-split/private file.
# ##############################
loginfo "Struct-Access-Split: Validate that the admin stored data in the private file..."

data=`read_sa_split private`
check match "$SAS_RDATA" "$data" \
  "Expected to read stored admin data, but didn't find it correctly!"
loginfo "Good. Admin performed data store."

# ##############################
# Attempt userspace heartbleed, we should see the admin|storedata now!
# ##############################
loginfo "Server One: Attempt userspace heartbleed, there should be an admin datastore op..."

# Attempt userspace heartbleed, see that the admin HAS stored the secret!
input_heartbleed $PORT_ONE | grep 'admin|storedata' > /dev/null 2>&1
check match "$?" "0" \
  "I should have seen admin|storedata--but I didn't!"
loginfo "Server One: Good. Heartbleed worked! We saw the admin data store op."

# ##############################
# Exfiltrate the admin secret with the vulcan neck pinch from the public
# /dev/struct-access/public file.
# ##############################
loginfo "Struct-Access: Exfiltrate the admin data from the struct-access/public file."

data=""
data=`read_sa public 2048 1`
check match "$SA_RDATA" "$data"

loginfo "Struct-Access: Good. Exfiltration SUCCESSFUL: $data"

# ##############################
# Attempt userspace heartbleed, we should see the admin|storedata now!
# ##############################
loginfo "Server Two: Attempt userspace heartbleed, there should be an admin datastore op..."

# Attempt userspace heartbleed, see that the admin HAS stored the secret!
input_heartbleed $PORT_TWO | grep 'admin|storedata' > /dev/null 2>&1
check match "$?" "0" \
  "I should have seen admin|storedata--but I didn't!"
loginfo "Server Two: Good. Heartbleed worked! We saw the admin data store op."

# ##############################
# Exfiltrate the admin secret with the vulcan neck pinch from the public
# /dev/struct-access-split/public file.
# ##############################
loginfo "Struct-Access-Split: Exfiltrate the admin data from the struct-access/public file."

data=""
data=`read_sa_split public 2048 1`
check match "$SAS_RDATA" "$data"

loginfo "Struct-Access-Split: Good. Exfiltration SUCCESSFUL: $data"

loginfo "Double server multistep test done!"

exit 0