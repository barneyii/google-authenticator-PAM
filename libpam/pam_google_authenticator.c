// PAM module for two-factor authentication.
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>

#ifdef linux
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#define HAS_SETFSUID
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "support.h"

#define MAX_PASS 200
#define MAXLINELENGTH 1024
#define MODULE_NAME "pam_google_authenticator"
#define SECRET      "~/.google_authenticator"
#define CHKTOKEN_HELPER "/usr/sbin/gauth_chktoken"
#define CONFIG_FILE "/etc/google-authenticator.conf"

#if defined(DEMO) || defined(TESTING)
static char error_msg[128];

const char *get_error_msg(void) __attribute__((visibility("default")));
const char *get_error_msg(void) {
  return error_msg;
}
#endif

extern void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

  va_list args;
  va_start(args, format);
#if !defined(TESTING)
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

static int converse(pam_handle_t *pamh, int nargs,
                    const struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static const char *get_user_name(pam_handle_t *pamh) {
  // Obtain the user's name
  const char *username;
  if (pam_get_item(pamh, PAM_USER, (void *)&username) != PAM_SUCCESS ||
      !username || !*username) {
    log_message(LOG_ERR, pamh,
                "No user name available when checking verification code");
    return NULL;
  }
  return username;
}

static char *get_secret_filename(pam_handle_t *pamh, const Params *params,
                                 const char *username, int *uid) {
  // Check whether the administrator decided to override the default location
  // for the secret file.
  const char *spec = params->secret_filename_spec
    ? params->secret_filename_spec : SECRET;

  // Obtain the user's id and home directory
  struct passwd pwbuf, *pw = NULL;
  char *buf = NULL;
  char *secret_filename = NULL;
  if (!params->fixed_uid) {
    #ifdef _SC_GETPW_R_SIZE_MAX
    int len = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (len <= 0) {
      len = 4096;
    }
    #else
    int len = 4096;
    #endif
    buf = malloc(len);
    *uid = -1;
    if (buf == NULL ||
        getpwnam_r(username, &pwbuf, buf, len, &pw) ||
        !pw ||
        !pw->pw_dir ||
        *pw->pw_dir != '/') {
    err:
      log_message(LOG_ERR, pamh, "Failed to compute location of secret file");
      free(buf);
      free(secret_filename);
      return NULL;
    }
  }

  // Expand filename specification to an actual filename.
  if ((secret_filename = strdup(spec)) == NULL) {
    goto err;
  }
  int allow_tilde = 1;
  for (int offset = 0; secret_filename[offset];) {
    char *cur = secret_filename + offset;
    char *var = NULL;
    size_t var_len = 0;
    const char *subst = NULL;
    if (allow_tilde && *cur == '~') {
      var_len = 1;
      if (!pw) {
        goto err;
      }
      subst = pw->pw_dir;
      var = cur;
    } else if (secret_filename[offset] == '$') {
      if (!memcmp(cur, "${HOME}", 7)) {
        var_len = 7;
        if (!pw) {
          goto err;
        }
        subst = pw->pw_dir;
        var = cur;
      } else if (!memcmp(cur, "${USER}", 7)) {
        var_len = 7;
        subst = username;
        var = cur;
      }
    }
    if (var) {
      size_t subst_len = strlen(subst);
      char *resized = realloc(secret_filename,
                              strlen(secret_filename) + subst_len);
      if (!resized) {
        goto err;
      }
      var += resized - secret_filename;
      secret_filename = resized;
      memmove(var + subst_len, var + var_len, strlen(var + var_len) + 1);
      memmove(var, subst, subst_len);
      offset = var + subst_len - resized;
      allow_tilde = 0;
    } else {
      allow_tilde = *cur == '/';
      ++offset;
    }
  }

  *uid = params->fixed_uid ? params->uid : pw->pw_uid;
  free(buf);
  return secret_filename;
}

static int setuser(int uid) {
#ifdef HAS_SETFSUID
  // The semantics for setfsuid() are a little unusual. On success, the
  // previous user id is returned. On failure, the current user id is returned.
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {
    setfsuid(old_uid);
    return -1;
  }
#else
  int old_uid = geteuid();
  if (old_uid != uid && seteuid(uid)) {
    return -1;
  }
#endif
  return old_uid;
}

static int setgroup(int gid) {
#ifdef HAS_SETFSUID
  // The semantics of setfsgid() are a little unusual. On success, the
  // previous group id is returned. On failure, the current groupd id is
  // returned.
  int old_gid = setfsgid(gid);
  if (gid != setfsgid(gid)) {
    setfsgid(old_gid);
    return -1;
  }
#else
  int old_gid = getegid();
  if (old_gid != gid && setegid(gid)) {
    return -1;
  }
#endif
  return old_gid;
}

static int drop_privileges(pam_handle_t *pamh, const char *username, int uid,
                           int *old_uid, int *old_gid) {
  // Try to become the new user. This might be necessary for NFS mounted home
  // directories.

  // First, look up the user's default group
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    log_message(LOG_ERR, pamh, "Cannot look up user id %d", uid);
    free(buf);
    return -1;
  }
  gid_t gid = pw->pw_gid;
  free(buf);

  int gid_o = setgroup(gid);
  int uid_o = setuser(uid);
  if (uid_o < 0) {
    if (gid_o >= 0) {
      if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o) {
        // Inform the caller that we were unsuccessful in resetting the group.
        *old_gid = gid_o;
      }
    }
    log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"",
                username);
    return -1;
  }
  if (gid_o < 0 && (gid_o = setgroup(gid)) < 0) {
    // In most typical use cases, the PAM module will end up being called
    // while uid=0. This allows the module to change to an arbitrary group
    // prior to changing the uid. But there are many ways that PAM modules
    // can be invoked and in some scenarios this might not work. So, we also
    // try changing the group _after_ changing the uid. It might just work.
    if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o) {
      // Inform the caller that we were unsuccessful in resetting the uid.
      *old_uid = uid_o;
    }
    log_message(LOG_ERR, pamh,
                "Failed to change group id for user \"%s\" to %d", username,
                (int)gid);
    return -1;
  }

  *old_uid = uid_o;
  *old_gid = gid_o;
  return 0;
}

static int check_secret_file_exists(pam_handle_t *pamh,
                                    struct Params *params,
                                    const char *secret_filename) {
  struct stat sb;
  if ( stat(secret_filename, &sb) < 0 ){
    if (params->nullok != NULLERR && errno == ENOENT) {
      // The user doesn't have a state file, but the admininistrator said
      // that this is OK. We still return an error from open_secret_file(),
      // but we remember that this was the result of a missing state file.
      params->nullok = SECRETNOTFOUND;
    } else {
      log_message(LOG_ERR, pamh, "Failed to read \"%s\"", secret_filename);
    }
    return -1;
  }
  return 0;
}

static int open_secret_file(pam_handle_t *pamh, const char *secret_filename,
                            struct Params *params, const char *username,
                            int uid, off_t *size, time_t *mtime) {
  // Try to open "~/.google_authenticator"
  *size = 0;
  *mtime = 0;
  int fd = open(secret_filename, O_RDONLY);
  struct stat sb;
  if (fd < 0 ||
      fstat(fd, &sb) < 0) {
    if (params->nullok != NULLERR && errno == ENOENT) {
      // The user doesn't have a state file, but the admininistrator said
      // that this is OK. We still return an error from open_secret_file(),
      // but we remember that this was the result of a missing state file.
      params->nullok = SECRETNOTFOUND;
    } else {
      log_message(LOG_ERR, pamh, "Failed to read \"%s\"", secret_filename);
    }
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  // Check permissions on secret file
  if ((sb.st_mode & 03577) != 0400 ||
      !S_ISREG(sb.st_mode) ||
      sb.st_uid != (uid_t)uid) {
    char buf[80];
    if (params->fixed_uid) {
      sprintf(buf, "user id %d", params->uid);
      username = buf;
    }
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" must only be accessible by %s",
                secret_filename, username);
    goto error;
  }

  // Sanity check for file length
  if (sb.st_size < 1 || sb.st_size > 64*1024) {
    log_message(LOG_ERR, pamh,
                "Invalid file size for \"%s\"", secret_filename);
    goto error;
  }

  *size = sb.st_size;
  *mtime = sb.st_mtime;
  return fd;
}

static char *get_first_pass(pam_handle_t *pamh) {
  const void *password = NULL;
  if (pam_get_item(pamh, PAM_AUTHTOK, &password) == PAM_SUCCESS &&
      password) {
    return strdup((const char *)password);
  }
  return NULL;
}

static char *request_pass(pam_handle_t *pamh, int echocode,
                          const char *prompt) {
  // Query user for verification code
  const struct pam_message msg = { .msg_style = echocode,
                                   .msg       = prompt };
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    log_message(LOG_ERR, pamh, "Did not receive verification code from user");
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

static int parse_user(pam_handle_t *pamh, const char *name, uid_t *uid) {
  char *endptr;
  errno = 0;
  long l = strtol(name, &endptr, 10);
  if (!errno && endptr != name && l >= 0 && l <= INT_MAX) {
    *uid = (uid_t)l;
    return 0;
  }
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len   = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len   = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwnam_r(name, &pwbuf, buf, len, &pw) || !pw) {
    free(buf);
    log_message(LOG_ERR, pamh, "Failed to look up user \"%s\"", name);
    return -1;
  }
  *uid = pw->pw_uid;
  free(buf);
  return 0;
}

static int parse_option(pam_handle_t *pamh, Params *params,
                        const char *option, int cfg_file){
  if (!memcmp(option, "secret=", 7)) {
    free((void *)params->secret_filename_spec);
    params->secret_filename_spec = strdup(option + 7);
  } else if (!memcmp(option, "user=", 5)) {
    uid_t uid;
    if (parse_user(pamh, option + 5, &uid) < 0) {
      return -1;
    }
    params->fixed_uid = 1;
    params->uid = uid;
  } else if (!strcmp(option, "try_first_pass")) {
    params->pass_mode = TRY_FIRST_PASS;
  } else if (!strcmp(option, "use_first_pass")) {
    params->pass_mode = USE_FIRST_PASS;
  } else if (!strcmp(option, "forward_pass")) {
    params->forward_pass = 1;
  } else if (!strcmp(option, "noskewadj")) {
    params->noskewadj = 1;
  } else if (!strcmp(option, "nullok")) {
    params->nullok = NULLOK;
  } else if (!strcmp(option, "echo-verification-code") ||
             !strcmp(option, "echo_verification_code")) {
    params->echocode = PAM_PROMPT_ECHO_ON;
  } else if ( !strcmp(option, "use_helper") || !memcmp(option, "use_helper=", 11)) {
    char *helper_path;
    params->use_helper = 1;
    if (!memcmp(option, "use_helper=", 11)) {
      helper_path = strdup(option+11);
      struct stat sb;
      if ( stat(helper_path, &sb) < 0 ){
        log_message(LOG_ERR, NULL, "failed to find \"%s\": %s", helper_path, strerror (errno));
        return -1;
      }
    } else {
      helper_path = CHKTOKEN_HELPER;
    }
    params->helper_path = helper_path;
  } else if (cfg_file && (
    !memcmp(option, "helper_owner=", 13) ||
    !strcmp(option, "counter-based") ||
    !strcmp(option, "time-based") ||
    !strcmp(option, "disallow-reuse") ||
    !strcmp(option, "allow-reuse") ||
    !strcmp(option, "force") ||
    !memcmp(option, "label=", 6) ||
    !strcmp(option, "quiet") ||
    !memcmp(option, "qr-mode=", 8) ||
    !memcmp(option, "rate-limit=", 11) ||
    !memcmp(option, "rate-time=", 10) ||
    !strcmp(option, "no-rate-limit") ||
    !memcmp(option, "window-size=", 12) ||
    !strcmp(option, "minimal-window"))) {
    // do nothing: these are options for google-authenticator utility
  } else {
    log_message(LOG_ERR, pamh, "Unrecognized option \"%s\"", option);
    return -1;
  }
  return 0;
}

static int parse_config_file(pam_handle_t *pamh, Params *params) {
  char input[MAXLINELENGTH];
  FILE *cf;
  int len;

  if ((cf = fopen(CONFIG_FILE, "r")) == NULL){
    log_message(LOG_ERR, NULL, "failed to find \"%s\": %s", CONFIG_FILE, strerror (errno));
    return -1;
  }

  while (fgets(input, MAXLINELENGTH, cf)){
    if (input[0] == '#')
      continue;
    len = strlen(input);
    if (len < 2)
      continue;
    if (input[len-1] == '\n')
      input[len-1] = '\0';

    if( parse_option(pamh, params, input, 1) < 0 ){
      return -1;
    }
  }
  return 0;
}

static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
                      Params *params) {
  params->echocode = PAM_PROMPT_ECHO_OFF;
  for (int i = 0; i < argc; ++i) {
    if( parse_option(pamh, params, argv[i], 0) < 0 ){
      return -1;
    }
  }
  return 0;
}

int read_forwarded_pw(char **pw){
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

static int run_helper_binary(pam_handle_t *pamh,
                             Params *params,
                             const char *secret_filename,
                             const char *pw,
                             char **forwarded_pw ){
  int retval = PAM_SESSION_ERR;
  int child, p2c[2], c2p[2];
  struct sigaction newsa, oldsa;

  // create pipes for bidirectional communication with helper
  if (pipe(p2c) != 0 || pipe(c2p) != 0 ) {
    log_message(LOG_ERR, pamh, "could not make pipe");
    return retval;
  }

  /*
   * This code arranges that the demise of the child does not cause
   * the application to receive a signal it is not expecting - which
   * may kill the application or worse.
   */
  memset(&newsa, '\0', sizeof(newsa));
  newsa.sa_handler = SIG_DFL;
  sigaction(SIGCHLD, &newsa, &oldsa);

  /* fork */
  child = fork();

  if (child == 0) { /* child fork */
    static char *envp[] = { NULL };
    char *args[] = { NULL, NULL, NULL, NULL, NULL };

    // close unneeded fds
    close(c2p[0]);
    close(p2c[1]);
    // redirect pipe to stdin
    dup2(p2c[0], STDIN_FILENO);
    // redirect stdout to pipe
    dup2(c2p[1], STDOUT_FILENO);


    // struct rlimit rlim;EFAULT
    // int i=0;
    // if (getrlimit(RLIMIT_NOFILE,&rlim)==0) {
    //         if (rlim.rlim_max >= MAX_FD_NO)
    //               rlim.rlim_max = MAX_FD_NO;
    //   for (i=0; i < (int)rlim.rlim_max; i++) {
    //   if (i != STDIN_FILENO)
    //     close(i);
    //   }
    // }

    /* exec binary helper */
    args[0] = strdup(params->helper_path);
    args[1] = strdup(secret_filename);

    if (params->nullok) {
      args[2]=strdup("nullok");
    } else {
      args[2]=strdup("nonull");
    }

    if (params->forward_pass) {
      args[3]=strdup("forward_pass");
    } else {
      args[3]=strdup("no_forward_pass");
    }

    execve(params->helper_path, args, envp);

    /* should not get here: exit with error */
    log_message(LOG_ERR, pamh, "helper binary is not available: %s (%s)", strerror(errno), errno);
    _exit(PAM_AUTHINFO_UNAVAIL);
  }
  else if (child > 0) { /* parent fork */
    // redirect pipe to stdin
    dup2(c2p[0], STDIN_FILENO);

    /* send the password to the child */
    if (pw != NULL) {
        if (dprintf(p2c[1], "%s\n", pw) != strlen(pw)+1) {
          log_message(LOG_ERR, pamh, "Cannot send password to helper: %s", strerror(errno));
          retval = PAM_AUTH_ERR;
        }
    } else {  /* blank password */
        if (dprintf(p2c[1], "\n") == -1) {
          log_message(LOG_ERR, pamh, "Cannot send password to helper: %s", strerror(errno));
          retval = PAM_AUTH_ERR;
        }
    }

    /* read forwarded_pw from child */
    if (params->forward_pass){
      read_forwarded_pw(forwarded_pw);
    }

    // close pipe fds
    close(p2c[0]); /* close here to avoid possible SIGPIPE above if helper fails */
    close(c2p[1]); /* ... */
    close(c2p[0]);
    close(p2c[1]);

    /* wait for helper to complete: */
    int rc = 0;
    while ((rc=waitpid(child, &retval, 0)) < 0 && errno == EINTR);
    if (rc<0) {
      log_message(LOG_ERR, pamh, "gauth_chktoken waitpid returned %d: %s", rc, strerror(errno));
      retval = PAM_AUTH_ERR;
    } else if (!WIFEXITED(retval)) {
      log_message(LOG_ERR, pamh, "gauth_chktoken abnormal exit: %d", retval);
      retval = PAM_AUTH_ERR;
    } else {
      retval = WEXITSTATUS(retval);
    }
  }
  else { /* fork failed */
    log_message(LOG_ERR, pamh, "fork failed");
    close(c2p[0]);
    close(c2p[1]);
    close(p2c[0]);
    close(p2c[1]);
    retval = PAM_AUTH_ERR;
  }

  sigaction(SIGCHLD, &oldsa, NULL);   /* restore old signal handler */

  log_message(LOG_INFO, pamh, "returning: %d", retval);
  return retval;
}

static int auth_helper(pam_handle_t *pamh,
                       Params *params,
                       const char *secret_filename){
  int rc = PAM_SESSION_ERR;
  char *forwarded_pw = NULL;
  char *pw = NULL;

  if (check_secret_file_exists(pamh, params, secret_filename) < 0) {
    if (params->nullok == SECRETNOTFOUND) {
      rc = PAM_SUCCESS;
    }
    return rc;
  }

  if (params->pass_mode == USE_FIRST_PASS ||
      params->pass_mode == TRY_FIRST_PASS) {
    pw = get_first_pass(pamh);
    rc = run_helper_binary(pamh, params, secret_filename, pw, &forwarded_pw);
  }
  if (params->pass_mode == PROMPT ||
      (rc != PAM_SUCCESS && params->pass_mode == TRY_FIRST_PASS) ) {
    pw = request_pass(pamh, params->echocode,
                            params->forward_pass ?
                            "Password & verification code: " :
                            "Verification code: ");
    rc = run_helper_binary(pamh, params, secret_filename, pw, &forwarded_pw);
  }

  log_message(LOG_INFO, pamh, "helper returned forwarded_pw: %s", forwarded_pw);

  // Update the system password, if we were asked to forward
  // the system password. We already removed the verification
  // code from the end of the password.
  if (rc == PAM_SUCCESS && params->forward_pass) {
    if (!forwarded_pw || pam_set_item(pamh, PAM_AUTHTOK, forwarded_pw) != PAM_SUCCESS) {
      rc = PAM_SESSION_ERR;
    }
  }

  // Clear out password and deallocate memory
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

static int auth_local(pam_handle_t *pamh,
                      Params *params,
                      const char *username,
                      char *secret_filename,
                      int uid ){
  int        rc = PAM_SESSION_ERR;
  int        fd = -1;
  off_t      filesize = 0;
  time_t     mtime = 0;
  char       *buf = NULL;
  uint8_t    *secret = NULL;
  int        secretLen = 0;
  int        old_uid = -1, old_gid = -1;

  // Read and process status file, then ask the user for the verification code.
  int early_updated = 0, updated = 0;
  if (!drop_privileges(pamh, username, uid, &old_uid, &old_gid) &&
      (fd = open_secret_file(pamh, secret_filename, params, username, uid,
                             &filesize, &mtime)) >= 0 &&
      (buf = read_file_contents(pamh, secret_filename, &fd, filesize)) &&
      (secret = get_shared_secret(pamh, secret_filename, buf, &secretLen)) &&
       rate_limit(pamh, secret_filename, &early_updated, &buf) >= 0) {
    long hotp_counter = get_hotp_counter(pamh, buf);
    int must_advance_counter = 0;
    char *pw = NULL, *saved_pw = NULL;
    for (int mode = 0; mode < 4; ++mode) {
      // In the case of TRY_FIRST_PASS, we don't actually know whether we
      // get the verification code from the system password or from prompting
      // the user. We need to attempt both.
      // This only works correctly, if all failed attempts leave the global
      // state unchanged.
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
      switch (mode) {
      case 0: // Extract possible verification code
      case 1: // Extract possible scratch code
        if (params->pass_mode == USE_FIRST_PASS ||
            params->pass_mode == TRY_FIRST_PASS) {
          pw = get_first_pass(pamh);
        }
        break;
      default:
        if (mode != 2 && // Prompt for pw and possible verification code
            mode != 3) { // Prompt for pw and possible scratch code
          rc = PAM_SESSION_ERR;
          continue;
        }
        if (params->pass_mode == PROMPT ||
            params->pass_mode == TRY_FIRST_PASS) {
          if (!saved_pw) {
            // If forwarding the password to the next stacked PAM module,
            // we cannot tell the difference between an eight digit scratch
            // code or a two digit password immediately followed by a six
            // digit verification code. We have to loop and try both
            // options.
            saved_pw = request_pass(pamh, params->echocode,
                                    params->forward_pass ?
                                    "Password & verification code: " :
                                    "Verification code: ");
          }
          if (saved_pw) {
            pw = strdup(saved_pw);
          }
        }
        break;
      }
      if (!pw) {
        continue;
      }

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

      if ((mode == 2 || mode == 3) && !params->forward_pass) {
        // We are explicitly configured so that we don't try to share
        // the password with any other stacked PAM module. We must
        // therefore verify that the user entered just the verification
        // code, but no password.
        if (*pw) {
          goto invalid;
        }
      }


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
    }

    // Update the system password, if we were asked to forward
    // the system password. We already removed the verification
    // code from the end of the password.
    if (rc == PAM_SUCCESS && params->forward_pass) {
      if (!pw || pam_set_item(pamh, PAM_AUTHTOK, pw) != PAM_SUCCESS) {
        rc = PAM_SESSION_ERR;
      }
    }

    // Clear out password and deallocate memory
    if (pw) {
      memset(pw, 0, strlen(pw));
      free(pw);
    }
    if (saved_pw) {
      memset(saved_pw, 0, strlen(saved_pw));
      free(saved_pw);
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
    }
  }

  // If the user has not created a state file with a shared secret, and if
  // the administrator set the "nullok" option, this PAM module completes
  // successfully, without ever prompting the user.
  if (params->nullok == SECRETNOTFOUND) {
    rc = PAM_SUCCESS;
  }

  // Persist the new state.
  if (early_updated || updated) {
    if (write_file_contents(pamh, secret_filename, filesize,
                            mtime, buf) < 0) {
      // Could not persist new state. Deny access.
      rc = PAM_SESSION_ERR;
    }
  }
  if (fd >= 0) {
    close(fd);
  }
  if (old_gid >= 0) {
    if (setgroup(old_gid) >= 0 && setgroup(old_gid) == old_gid) {
      old_gid = -1;
    }
  }
  if (old_uid >= 0) {
    if (setuser(old_uid) < 0 || setuser(old_uid) != old_uid) {
      log_message(LOG_EMERG, pamh, "We switched users from %d to %d, "
                  "but can't switch back", old_uid, uid);
    }
  }
  free(secret_filename);

  // Clean up
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

static int google_authenticator(pam_handle_t *pamh, int flags,
                                int argc, const char **argv) {
  int        rc = PAM_SESSION_ERR;
  const char *username;
  char *secret_filename = NULL;
  int        uid = -1;


#if defined(DEMO) || defined(TESTING)
  *error_msg = '\000';
#endif

  // Handle optional arguments that configure our PAM module
  Params params = { 0 };

#if !defined(TESTING)
  if (parse_config_file(pamh, &params) < 0){
    return rc;
  }
#endif

  if (parse_args(pamh, argc, argv, &params) < 0) {
    return rc;
  }

  if ((username = get_user_name(pamh)) &&
      (secret_filename = get_secret_filename(pamh, &params, username, &uid)) ){
    if (params.use_helper){
      rc = auth_helper(pamh, &params, secret_filename);
    } else {
      rc = auth_local(pamh, &params, username, secret_filename, uid);
    }
  }

  return rc;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
  __attribute__((visibility("default")));
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                     const char **argv)
  __attribute__((visibility("default")));
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                     const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
  __attribute__((visibility("default")));
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, flags, argc, argv);
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  pam_sm_open_session,
  NULL,
  NULL
};
#endif
