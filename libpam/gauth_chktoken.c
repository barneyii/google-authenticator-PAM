

#include <sys/param.h>

#define MAX_PASS 208 /* cater for pw and code when using forward_pass */
#define MAX_USERNAME 32

#include <errno.h>
#include <fcntl.h>

#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "support.h"

#define MODULE_NAME "gauth_chktoken";

extern void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
  const char *logname = MODULE_NAME

  va_list args;
  va_start(args, format);
#if !defined(DEMO) && !defined(TESTING)
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  closelog();
#else
  if (!*error_msg) {
    vsnprintf(error_msg, sizeof(error_msg), format, args);
  }
#endif

  va_end(args);

  if (priority == LOG_EMERG) {
    // Something really bad happened. There is no way we can proceed safely.
    _exit(1);
  }
}

static int open_secret_file(const char *secret_filename,
                            struct Params *params,
                            const int owner_uid,
                            off_t *size,
                            time_t *mtime) {
  // Try to open secret file
  *size = 0;
  *mtime = 0;
  int fd = open(secret_filename, O_RDONLY);
  struct stat sb;
  if (fd < 0 || fstat(fd, &sb) < 0) {
    log_message(LOG_ERR, NULL, "Failed to read \"%s\": %s", secret_filename, strerror(errno));
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  // Check permissions on secret file
  if ((sb.st_mode & 03577) != 0400 ||
      !S_ISREG(sb.st_mode) ||
      sb.st_uid != (uid_t)owner_uid)
  {
    char owner[MAX_USERNAME+1];
    strcpy(owner, getpwuid(owner_uid)->pw_name);

    log_message(LOG_ERR, NULL,
                "Secret file \"%s\" must only be accessible by %s",
                secret_filename, owner);
    goto error;
  }

  // Sanity check for file length
  if (sb.st_size < 1 || sb.st_size > 64*1024) {
    log_message(LOG_ERR, NULL,
                "Invalid file size for \"%s\"", secret_filename);
    goto error;
  }

  *size = sb.st_size;
  *mtime = sb.st_mtime;
  return fd;
}


static int parse_args(const int argc, const char **argv,
                      Params *params,
                      char **secret_filename,
                      int *owner_uid) {
  // find owner of chktoken helper
  const char *helper_filename = argv[0];
  int fd = open(helper_filename, O_RDONLY);
  struct stat sb;
  if (fd < 0 || fstat(fd, &sb) < 0) {
    log_message(LOG_ERR, NULL, "Failed to read \"%s\"", helper_filename);
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }
  *owner_uid = sb.st_uid;

  // param 1: secret_filename
  *secret_filename = strdup(argv[1]);

  return 0;
}

static int check_pw(const char *secret_filename,
                    const char *saved_pw,
                    const int owner_uid,
                    char **forwarded_pw,
                    Params *params) {
  pam_handle_t *pamh = NULL;
  int          rc = PAM_SESSION_ERR;
  int          fd = -1;
  off_t        filesize = 0;
  time_t       mtime = 0;
  char         *buf = NULL;
  uint8_t      *secret = NULL;
  int          secretLen = 0;
  char         *pw = NULL;
  long         hotp_counter = -1;
  int          must_advance_counter = 0;

  int early_updated = 0, updated = 0;
  if ((fd = open_secret_file(secret_filename, params, owner_uid, &filesize, &mtime)) >= 0 &&
      (buf = read_file_contents(pamh, secret_filename, &fd, filesize)) &&
      (secret = get_shared_secret(pamh, secret_filename, buf, &secretLen)) &&
       rate_limit(pamh, secret_filename, &early_updated, &buf) >= 0 &&
      (hotp_counter = get_hotp_counter(pamh, buf)) >= 0 ) {

    for (int mode = 0; mode < 2; ++mode) {
      // we don't know whether the code is a 6-digit verification code or an 8-digit scratch code
      // so try both, starting with verification code
      if (updated || pw) {
        // Oops. There is something wrong with the internal logic of our
        // code. This error should never trigger. The unittest checks for
        // this.
        if (pw) {
          memset(pw, 0, strlen(pw));
          free(pw);
          pw = NULL;
        }
        rc = PAM_SESSION_ERR;
        break;
      }

      pw = strdup(saved_pw);

      // We are often dealing with a combined password and verification
      // code. Separate them now.
      int pw_len = strlen(pw);
      int expected_len = mode & 1 ? 8 : 6;
      char ch;
      if (pw_len < expected_len ||
          // Verification are six digits starting with '0'..'9',
          // scratch codes are eight digits starting with '1'..'9'
          (ch = pw[pw_len - expected_len]) > '9' ||
          ch < (expected_len == 8 ? '1' : '0')) {
      invalid:
        memset(pw, 0, pw_len);
        free(pw);
        pw = NULL;
        continue;
      }
      char *endptr;
      errno = 0;
      long l = strtol(pw + pw_len - expected_len, &endptr, 10);
      if (errno || l < 0 || *endptr) {
        goto invalid;
      }
      int code = (int)l;
      memset(pw + pw_len - expected_len, 0, expected_len);

      // Check all possible types of verification codes.
      switch (check_code(pamh, secret_filename, &updated,
                         &buf, secret, secretLen, code,
                         params, hotp_counter,
                         &must_advance_counter)){
      case 0:
        rc = PAM_SUCCESS;
        break;
      case 1:
        goto invalid;
      default:
        break;
      }

      break;
    } // end loop

    if (pw) {
      // Update forwarded_pw
      // We already removed the verification code from the end of the password.
      *forwarded_pw = strdup(pw);

      // Clear out password and deallocate memory
      memset(pw, 0, strlen(pw));
      free(pw);
    }

    // If an hotp login attempt has been made, the counter must always be
    // advanced by at least one.
    if (must_advance_counter) {
      char counter_str[40];
      sprintf(counter_str, "%ld", hotp_counter + 1);
      if (set_cfg_value(pamh, "HOTP_COUNTER", counter_str, &buf) < 0) {
        rc = PAM_SESSION_ERR;
      }
      updated = 1;
    }

    // If nothing matched, display an error message
    if (rc != PAM_SUCCESS) {
      log_message(LOG_ERR, pamh, "Invalid verification code");
    } else log_message(LOG_INFO, pamh, "accepted!!!");
  }

  // Persist the new state.
  if (early_updated || updated) {
    if (write_file_contents(pamh, secret_filename, filesize,
                            mtime, buf) < 0) {
      // Could not persist new state. Deny access.
      rc = PAM_SESSION_ERR;
    }
  }

  // Clean up
  if (fd >= 0) {
    close(fd);
  }
  if (buf) {
    memset(buf, 0, strlen(buf));
    free(buf);
  }
  if (secret) {
    memset(secret, 0, secretLen);
    free(secret);
  }
  return rc;
}

int read_password(char **pw){
  char *buf = malloc(MAX_PASS+1);
  if( (*pw = fgets(buf, MAX_PASS, stdin)) ) {
    // remove newline
    int len = strlen(buf);
    if( buf[len-1] == '\n')
      buf[len-1] = 0;

    return 0;
  } else {
    return -1;
  }
}

int main(int argc, const char *argv[]) {
  int        rc = PAM_SESSION_ERR;
  pam_handle_t *pamh = NULL;
  Params     params = { 0 };
  char       *secret_filename = NULL;
  char       *pw = NULL;
  int        owner_uid = -1;
  char       *forwarded_pw = NULL;

  if (isatty(STDIN_FILENO) || argc != 4 ) {
    log_message(LOG_NOTICE, pamh, "inappropriate use of chktoken helper binary");
    return PAM_SYSTEM_ERR;
  }

  if (parse_args(argc, argv, &params, &secret_filename, &owner_uid) < 0) {
    return rc;
  }
  if(read_password(&pw) < 0){
    return rc;
  }

  rc = check_pw(secret_filename, pw, owner_uid, &forwarded_pw, &params);

  // return forwarded_pw via pipe
  if (!forwarded_pw)
    forwarded_pw = strdup("");
  if (dprintf(STDOUT_FILENO, "%s\n", forwarded_pw) != strlen(forwarded_pw)+1) {
    log_message(LOG_ERR, pamh, "Cannot send forwarded password back to Google Auth PAM: %s", strerror(errno));
  }

  // clean up
  if (pw) {
    memset(pw, 0, strlen(pw));
    free(pw);
  }
  if (forwarded_pw) {
    memset(forwarded_pw, 0, strlen(forwarded_pw));
    free(forwarded_pw);
  }

  return rc;
}

