
#ifndef _SUPPORT_H_
#define _SUPPORT_H_

#include <time.h>
#include <stdint.h>

#include <security/pam_modules.h>

typedef struct Params {
  const char *secret_filename_spec;
  enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
  int        noskewadj;
  int        echocode;
  int        fixed_uid;
  uid_t      uid;
  enum { PROMPT = 0, TRY_FIRST_PASS, USE_FIRST_PASS } pass_mode;
  int        forward_pass;
} Params;


extern void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...);

char *read_file_contents(pam_handle_t *pamh,
                         const char *secret_filename, int *fd,
                         off_t filesize);

int write_file_contents(pam_handle_t *pamh, const char *secret_filename,
                        off_t old_size, time_t old_mtime,
                        const char *buf);

char *get_cfg_value(pam_handle_t *pamh, const char *key,
                    const char *buf);

uint8_t *get_shared_secret(pam_handle_t *pamh,
                           const char *secret_filename,
                           const char *buf, int *secretLen);

int set_cfg_value(pam_handle_t *pamh, const char *key, const char *val,
                  char **buf);

long get_hotp_counter(pam_handle_t *pamh, const char *buf);

int rate_limit(pam_handle_t *pamh, const char *secret_filename,
               int *updated, char **buf);

int check_code(pam_handle_t *pamh,
               const char *secret_filename,
               int *updated,
               char **buf,
               const uint8_t *secret,
               int secretLen,
               int code,
               Params *params,
               long hotp_counter,
               int *must_advance_counter);

#endif /* _SUPPORT_H_ */
