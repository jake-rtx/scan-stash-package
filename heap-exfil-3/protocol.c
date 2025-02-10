#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/fsuid.h>
#include <errno.h>


#include "config.h"
#include "zero.h"
#include "sessionstore.h"
#include "protocol.h"

#define SESSION_ADMIN "admin"

#define OP_OPEN_FILE "openfile"
#define OP_HEARTBLEED "heartbleed"
#define OP_DUMP_SESSIONS "dumpsessions"
#define OP_OVERRUN "overrun"
#define OP_STORE_DATA "storedata"

#define OP_OPEN_FILE_SUCCESS "SUCCESS"
#define OP_OPEN_FILE_FAIL "FAILURE"

#define OP_STORE_DATA_SUCCESS "SUCCESS"
#define OP_STORE_DATA_FAIL "FAILURE"

/* admin has read, others do not*/
/* Until we discover _if_ this must be true, this file must be 14 characters
 * long, chmod 400, and owned by root.
*/
#define ROOT_PRIV_TEST_FILE "/tmp/serv-file"

/* struct-access connection. */
extern char *ROOT_STORE_DATA_FILE;
extern char *USER_STORE_DATA_FILE;

struct dispatch_object {
  struct responsedata * (*p_openfile)(int);
  struct responsedata * (*p_dumpsessions)(int);
  struct responsedata * (*p_heartbleed)(const char *);
  struct responsedata * (*p_overrun)(int, const char *);
  struct responsedata * (*p_storedata)(int, const char *);
};

struct dispatch_object function_table;

static int upfsprivs() {
  /* update to root so we can do things like open slabinfo */
  return setfsuid(0);
}

static void restoreprivs(int olduid) {
  /* restore permission */
  setfsuid(olduid);
}

/*
 * Inspired by an old weakness in openssh server,
 * where a user supplied buffer should be echoed, but the
 * implementation allows the attacker to control the buffer size
*/
static responsedata * op_heartbleed(const char * attacker_input) {
  responsedata * response = malloc(sizeof (struct responsedata) * 1);

  /* This whole thing works b/c of heap memory layout.
   * in this code base, the zero copy pool is allocated on the heap prior
   * to the session logging pool. If the attacker is on a thread using a
   * zero copy buffer (which attacker_input here will likely be), then
   * this faulty logic can be used to overrun a copy operation into the
   * session space to exfile session cookies (e.g., to have admin rights).
  */

  /* find the pipe in the users input */
  char * idx = strstr(attacker_input, "|");
  if (idx != NULL) {
    /* null the pipe */
    *idx = '\0';

      /* attacker is providing size and buffer for echoing in the from "4096|x" */
    response->bufsz = atoi(attacker_input);
    response->buf = (char *) malloc(sizeof(char)*response->bufsz);
    /* idx is small ideally, like a single character 'x',
     * so this is an excessive copy starting from the zero copy buffer if the attacker is lucky
     */
    memcpy((void*) response->buf, (void*) ++idx, response->bufsz);

    printf("attacker is attempting to copy %d bytes of heap. starting from address: %p\n", response->bufsz, idx);
  } else {
    /* malformed input */
    response->bufsz = 6;
    response->buf = malloc(sizeof(char)*response->bufsz);
    memcpy(response->buf, "BADIO\0", response->bufsz);
  }

  return response;
}

/* to support simple c-strings, we just concat responses. */
static responsedata * op_dumpsessions(int admin) {
  char * idx = NULL;
  int i = 0;
  int ct = 0;
  int len = 0;
  char * ret = NULL;
  char * retroot = NULL;
  responsedata * response = malloc (sizeof(struct responsedata) * 1);
  response->buf = NULL;
  response->bufsz = -1;

  if (admin) {
    /* count */
    idx = (char *) session_peak();
    while (i<SESSION_HISTORY) {
      if (*idx != '\0') {
        ct++;
        printf("[slot: %d] '%s'\n", i, idx);
      } else {
        printf("[slot: %d] is empty: \n", i);
      }
      i++;
      idx = &((char*)session_peak())[i*BUFSIZE];
    }
    if (ct > 0) {
      printf("%d session entries have logging data. setup return on heap.\n", ct);

      /* alloc ret */
      retroot = ret = (char *) calloc(ct, BUFSIZE);

      /* copy data */
      idx = (char *) session_peak();
      i = 0;
      while(i<SESSION_HISTORY) {
        if (*idx != '\0') {

          len = strlen(idx);
          memcpy((void*) ret, (void*) idx, len);
          ret+=len;

        }
        i++;
        idx = &((char*)session_peak())[i*BUFSIZE];
      }

      printf("'%s'\n", retroot);

      response->buf = retroot;
      response->bufsz = strlen(retroot);
    }

  }

  return response;
}

static responsedata * cmd_test_open_file(const char * file) {
  responsedata * ret = malloc (sizeof(struct responsedata) * 1);
  int fd = open (file, O_RDONLY);

  if (fd == -1) {
    perror("could not open file");
    ret->buf = strdup(OP_OPEN_FILE_FAIL);
    ret->bufsz = strlen(OP_OPEN_FILE_FAIL) + 1;
  } else {
    printf("successfully opened %s\n", file);
    ret->buf = strdup(OP_OPEN_FILE_SUCCESS);
    ret->bufsz = strlen(OP_OPEN_FILE_SUCCESS) + 1;
    close(fd);
  }

  return ret;
}

static responsedata * op_openfile(int asadmin) {
  responsedata * ret;
  int olduid;
  if (asadmin) {
    olduid = upfsprivs();
  }

  ret = cmd_test_open_file(ROOT_PRIV_TEST_FILE);

  if (asadmin) {
    restoreprivs(olduid);
  }

  return ret;
}

/* Write the entire buffer instead of doing a quick write(). Copied from struct_access_tool.c */
static int store_write_all(const int fd, const char *buf, const int count) {
  const char *ptr = buf;
  int nwritten = 0;
  // write bytes from the data buffer matching the given len/count (bytecount)
  int remaining = count;

  do {
    nwritten = write(fd, ptr, remaining);
    if (nwritten < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    remaining -= nwritten;
    ptr += nwritten;
  } while (remaining > 0);

  return count;
}

static responsedata * cmd_store_data(const char * file, const int bytecount, const char *databytes) {
  responsedata * ret = malloc (sizeof(struct responsedata) * 1);
  int fd;
  /* open the file to write to */
  fd = open (file, O_RDWR, 0600);

  if (fd == -1) {
    perror("could not open file");
    ret->buf = strdup(OP_STORE_DATA_FAIL);
    ret->bufsz = strlen(OP_STORE_DATA_FAIL) + 1;
    return ret;
  }

  if (databytes != NULL && bytecount >= 0){
    if(bytecount > strlen(databytes)) {
      perror("Byte count exceed the number of bytes in data string.\n");
      ret->buf = strdup(OP_STORE_DATA_FAIL);
      ret->bufsz = strlen(OP_STORE_DATA_FAIL) + 1;
      return ret;
    }
    /* do write */
    int len = bytecount;
    int write_ret = store_write_all(fd, databytes, len);
    if(write_ret != len) {
      fprintf(stderr, "could not write data to file: %s %s(%d)\n", file, strerror(errno), errno);
      perror("");
      ret->buf = strdup(OP_STORE_DATA_FAIL);
      ret->bufsz = strlen(OP_STORE_DATA_FAIL) + 1;
      return ret;
    }
  } else {
    /* malformed input */
    fprintf(stderr, "Malformed input data: %s\n", databytes);
    perror("");
    ret->buf = strdup(OP_STORE_DATA_FAIL);
    ret->bufsz = strlen(OP_STORE_DATA_FAIL) + 1;
    return ret;
  }

  printf("successfully stored data %s\n", file);
  ret->buf = strdup(OP_STORE_DATA_SUCCESS);
  ret->bufsz = strlen(OP_STORE_DATA_SUCCESS) + 1;

  close(fd);
  return ret;
}

static responsedata * op_storedata(int asadmin, const char *input_data) {
  responsedata * ret;
  int olduid;
  const char *file_to_open = NULL;

  /* NOTE: Force that users and admins store into different files. */
  if (asadmin) {
    if (access(ROOT_STORE_DATA_FILE, F_OK) == 0) {
      file_to_open = ROOT_STORE_DATA_FILE;
    }
    olduid = upfsprivs();
  } else {
    if (access(USER_STORE_DATA_FILE, F_OK) == 0) {
      file_to_open = USER_STORE_DATA_FILE;
    }
  }

  /* copy the input data into a char pointer */
  char *data = strdup(input_data);
  /* grab the pipe + string */
  char *idx = strstr(input_data, "|");

  /* Check if the file to open exists. */
  if(idx != NULL && file_to_open != NULL) {
    /* grab the string without the pipe */
    char *databytes = idx + 1;
    /* grab the data 'bytecount' from in front of the pipe */
    char *bytestr = strtok(data, "|");
    int bytecount = atoi(bytestr);
    /* send the bytecount and data to store_data */
    ret = cmd_store_data(file_to_open, bytecount, databytes);

  } else {
    perror("Ill formatted user input or file to open does not exist.\n");
  }

  if (asadmin) {
    restoreprivs(olduid);
  }

  free(data);
  return ret;
}

static responsedata * op_overrun(int asadmin, const char * attacker_input) {
  responsedata * response;
  int changePriv[1] = {asadmin};

  // Split here

  char filename[15] = {0};
  char * idx = strstr(attacker_input, "|");
  if (idx != NULL) {
    *idx = '\0';
    int size = atoi(attacker_input);
    printf("Attacker size: %d\n", size);
    memcpy((void*) filename, (void*) ++idx, size);
    filename[14] = '\0';
  } else {
    response = malloc (sizeof(struct responsedata) * 1);
    response->bufsz = 6;
    response->buf = malloc(sizeof(char)*response->bufsz);
    memcpy(response->buf, "BADIO\0", response->bufsz);
  }

  int olduid;
  if (*changePriv) {
    olduid = upfsprivs();
  }

  printf("Attempting to read from file: %s\n", filename);
  response = cmd_test_open_file(filename);

  if (*changePriv) {
    restoreprivs(olduid);
  }

  return response;
}

/* asadmin is not a unique concept, powershell has verb/runas, linux has sudo */
static responsedata * process_cmd(const char * cmd, int asadmin) {
  responsedata * ret;

  if (strncmp(cmd, OP_OPEN_FILE, strlen(OP_OPEN_FILE)) == 0) {
    if (function_table.p_openfile != NULL) {
      return (*function_table.p_openfile)(asadmin);
    }
  }

  if (strncmp(cmd, OP_DUMP_SESSIONS, strlen(OP_DUMP_SESSIONS)) == 0) {
    if (function_table.p_dumpsessions != NULL) {
      return (*function_table.p_dumpsessions)(asadmin);
    }
  }

  if (strncmp(cmd, OP_HEARTBLEED, strlen(OP_HEARTBLEED)) == 0) {
    /* heartbleed|<ascii-int>|<char-buf>
          minimum size "heartbleed|9|a" */
    if ((strlen(OP_HEARTBLEED)+4) <= strlen(cmd)) {
      if (function_table.p_heartbleed != NULL) {
        /* past some minimal input validation. skip the 'heartbleed|' */
        return (*function_table.p_heartbleed)(&cmd[strlen(OP_HEARTBLEED) + 1]);
      }
    }
  }

  if (strncmp(cmd, OP_OVERRUN, strlen(OP_OVERRUN)) == 0) {
    /* overrun|<ascii-int>|<char-buf> */
    if ((strlen(OP_OVERRUN)+4) <= strlen(cmd)) {
      if (function_table.p_overrun != NULL) {
        return (*function_table.p_overrun)(asadmin, &cmd[strlen(OP_OVERRUN) + 1]);
      }
    }
  }

  if (strncmp(cmd, OP_STORE_DATA, strlen(OP_STORE_DATA)) == 0) {
    /* storedata|<bytecount>|<databytes> */
    if ((strlen(OP_STORE_DATA)+4) <= strlen(cmd)) {
      if (function_table.p_storedata != NULL) {
        return (*function_table.p_storedata)(asadmin, &cmd[strlen(OP_STORE_DATA) + 1]);
      }
    }
  }

  /* default return */
  ret = malloc (sizeof (struct responsedata) * 1);
  ret->bufsz = 5;
  ret->buf = malloc(ret->bufsz);
  strncpy(ret->buf, "NACK\0", ret->bufsz);

  return ret;
}

void init_protocol_elements(bool enable_op_dumpsession,
                bool enable_op_openfile,
                bool enable_op_heartbleed,
                bool enable_op_overrun,
                bool enable_op_storedata) {
  memset((void*) &function_table, 0x00, sizeof(struct dispatch_object));
  if (enable_op_dumpsession) {
    function_table.p_dumpsessions = op_dumpsessions;
    printf("Enable op_dumpsessions\n");
  }
  if (enable_op_openfile) {
    function_table.p_openfile = op_openfile;
    printf("Enable op_openfile\n");
  }
  if (enable_op_heartbleed) {
    function_table.p_heartbleed = op_heartbleed;
    printf("Enable op_heartbleed\n");
  }
  if (enable_op_overrun) {
    function_table.p_overrun = op_overrun;
    printf("Enable op_overrun\n");
  }
  if (enable_op_storedata) {
    function_table.p_storedata = op_storedata;
    printf("Enable op_storedata\n");
  }
}

responsedata * auth_and_execute(char * io) {
  /*
         * simple parser for simple top-level "<session>|<command>" protocol.
   */
  char * session = io;
  char * cmd = strstr(io, "|");
  *cmd = '\0';
  cmd++;

  /* Log session info and command on heap */
  session_log(session, cmd);

  /* Check session/cookie/user and do something in that context */
  if (strncmp(SESSION_ADMIN, session, 5) == 0) {
    return process_cmd(cmd, 1);
  } else {
    return process_cmd(cmd, 0);
  }
}
