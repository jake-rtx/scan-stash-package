# Usage

% ./server
././server [-e <EUID>] [-d] [-o] [-h] [-r]
  -e <EUID>: a user id (as required int) to change to after the libc:bind on port 88.
  -d: enable protocol op_dumpsession
  -o: enable protocol op_openfile
  -h: enable protocol op_heartbleed
  -r: enable protocol op_overrun
././server must be launched by a root user.

# Example of running as root with a UID of 1832003151

root@MA15416APAULOS:/home/apaulos/Downloads/DevVM/BBN/arc/source/examples/user-space/heap-exfil-2# ./server -e 1832003151 -doh
Set effective privs to 1832003151
Allocated zero copy pool at 0x56a5ad3ba6b0
Allocated session store at 0x56a5ad3bcef0
Enable op_dumpsessions
Enable op_openfile
Enable op_heartbleed

# Providing inputs

see ./inputs/*.sh scripts


