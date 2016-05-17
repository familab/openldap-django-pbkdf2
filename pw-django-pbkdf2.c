#define _GNU_SOURCE

#include "portable.h"
#include <slap.h>
#include <ac/string.h>
#include "lber_pvt.h"
#include "lutil.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_GNUTLS
#define PBKDF2_LIB "Nettle"
#include <nettle/pbkdf2.h>
#else
#error Unsupported crypto backend.
#endif

static int pbkdf2_iteration = 24000;
#define PBKDF2_SHA256_SALT_SIZE 12
#define PBKDF2_MAX_SALT_SIZE 64
#define PBKDF2_SHA256_DK_SIZE 32

const struct berval pbkdf2_sha256_scheme = BER_BVC("{PBKDF2-SHA256}");

static int pbkdf2_format(
	const struct berval *sc,
	int iteration,
	const struct berval *salt,
	const struct berval *dk,
	struct berval *msg)
{
	int rc, msg_len;
	char salt_b64[LUTIL_BASE64_ENCODE_LEN(PBKDF2_MAX_SALT_SIZE) + 1];
	char dk_b64[LUTIL_BASE64_ENCODE_LEN(PBKDF2_SHA256_DK_SIZE) + 1];

	rc = lutil_b64_ntop((unsigned char *)salt->bv_val, salt->bv_len,
						salt_b64, sizeof(salt_b64));

	if(rc < 0){
		return LUTIL_PASSWD_ERR;
	}
	rc = lutil_b64_ntop((unsigned char *)dk->bv_val, dk->bv_len,
						dk_b64, sizeof(dk_b64));
	if(rc < 0){
		return LUTIL_PASSWD_ERR;
	}
	msg_len = asprintf(&msg->bv_val, "%s%d$%s$%s",
						   sc->bv_val, iteration,
						   salt_b64, dk_b64);
	if(msg_len < 0){
		msg->bv_len = 0;
		return LUTIL_PASSWD_ERR;
	}

	msg->bv_len = msg_len;
	return LUTIL_PASSWD_OK;
}

static int pbkdf2_encrypt(
	const struct berval *scheme,
	const struct berval *passwd,
	struct berval *msg,
	const char **text)
{
	unsigned char salt_value[PBKDF2_SHA256_SALT_SIZE] = {0};
	char salt_b64[LUTIL_BASE64_ENCODE_LEN(PBKDF2_MAX_SALT_SIZE) + 1] = {0};
  size_t salt_len;
	struct berval salt;
	unsigned char dk_value[PBKDF2_SHA256_DK_SIZE] = {0};
	struct berval dk;
	int iteration = pbkdf2_iteration;
	int rc;

	salt.bv_val = (char *)salt_value;
	salt.bv_len = sizeof(salt_value);
	dk.bv_val = (char *)dk_value;
	dk.bv_len = PBKDF2_SHA256_DK_SIZE;

	if(lutil_entropy((unsigned char *)salt.bv_val, salt.bv_len) < 0){
		return LUTIL_PASSWD_ERR;
	}

  rc = lutil_b64_ntop((unsigned char *)salt.bv_val, salt.bv_len, salt_b64, PBKDF2_MAX_SALT_SIZE + 1);
  if(rc < 0){
    return LUTIL_PASSWD_ERR;
  }
  salt_len = rc;

#ifdef HAVE_GNUTLS
  pbkdf2_hmac_sha256 (passwd->bv_len, (const uint8_t *) passwd->bv_val,
  		    (unsigned) iteration,
  		    salt_len, (unsigned char *) salt_b64,
  		    sizeof(dk_value), (uint8_t *) dk_value);
#endif

#ifdef SLAPD_DJANGO_PBKDF2_DEBUG
	printf("Encrypt for %s\n", scheme->bv_val);
	printf("  Library:\t%s\n", PBKDF2_LIB);
	printf("  Password:\t%s\n", passwd->bv_val);

	printf("  Salt:\t\t");
	int i;
	for(i=0; i<salt.bv_len; i++){
		printf("%02x", salt_value[i]);
	}
	printf("\n");
	printf("  Iteration:\t%d\n", iteration);

	printf("  DK:\t\t");
	for(i=0; i<dk.bv_len; i++){
		printf("%02x", dk_value[i]);
	}
	printf("\n");
#endif

	rc = pbkdf2_format(scheme, iteration, &salt, &dk, msg);

#ifdef SLAPD_DJANGO_PBKDF2_DEBUG
	printf("  Output:\t%s\n", msg->bv_val);
#endif

	return rc;
}

static int pbkdf2_check(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{

	int rc;
	int iteration;

	/* salt_value require PBKDF2_MAX_SALT_SIZE + 1 in lutil_b64_pton. */
	unsigned char salt_value[PBKDF2_MAX_SALT_SIZE + 1] = {0};
	char salt_b64[LUTIL_BASE64_ENCODE_LEN(PBKDF2_MAX_SALT_SIZE) + 1] = {0};
  size_t salt_len;
	/* dk_value require PBKDF2_SHA256_DK_SIZE + 1 in lutil_b64_pton. */
	unsigned char dk_value[PBKDF2_SHA256_DK_SIZE + 1] = {0};
	char dk_b64[LUTIL_BASE64_ENCODE_LEN(PBKDF2_SHA256_DK_SIZE) + 1] = {0};
	unsigned char input_dk_value[PBKDF2_SHA256_DK_SIZE] = {0};
	size_t dk_len;

#ifdef SLAPD_DJANGO_PBKDF2_DEBUG
  // Debug( LDAP_DEBUG_CONFIG, "%s: ",
  //   "\"baseObject\" already provided (will be overwritten)\n",
  //   c->log, 0, 0 );
	printf("Checking for %s\n", scheme->bv_val);
	printf("  Stored Value:\t%s\n", passwd->bv_val);
	printf("  Input Cred:\t%s\n", cred->bv_val);
#endif

	iteration = atoi(passwd->bv_val);
	if(iteration < 1){
		return LUTIL_PASSWD_ERR;
	}

  char *ptr;
  ptr = strchr(passwd->bv_val, '$');
	if(!ptr){
		return LUTIL_PASSWD_ERR;
	}
  ptr++;

  strncpy(salt_b64, ptr, strcspn(ptr, "$"));

  ptr = strchr(ptr, '$');
  if(!ptr){
    return LUTIL_PASSWD_ERR;
  }
  ptr++;

  strncpy(dk_b64, ptr, strcspn(ptr, "$"));

	/* The targetsize require PBKDF2_MAX_SALT_SIZE + 1 in lutil_b64_pton. */
	rc = lutil_b64_pton(salt_b64, salt_value, PBKDF2_MAX_SALT_SIZE + 1);
	if(rc < 0){
		return LUTIL_PASSWD_ERR;
	}

  salt_len = rc;

	/* The targetsize require PBKDF2_SHA256_DK_SIZE + 1 in lutil_b64_pton. */
	rc = lutil_b64_pton(dk_b64, dk_value, sizeof(dk_value));
	if(rc < 0){
		return LUTIL_PASSWD_ERR;
	}

  dk_len = rc;

#ifdef HAVE_GNUTLS
  // pbkdf2_hmac_sha256 (dk_len, input_dk_value,
  // 		    iteration,
  // 		    strlen(salt_value), salt_value,
  // 		    dk_len, dk_value);
  pbkdf2_hmac_sha256 (cred->bv_len, (const uint8_t *) cred->bv_val,
          (unsigned) iteration,
          strlen(salt_b64), (unsigned char *) salt_b64,
          dk_len, (uint8_t *) input_dk_value);
#endif

	rc = memcmp(dk_value, input_dk_value, dk_len);
#ifdef SLAPD_DJANGO_PBKDF2_DEBUG
	printf("  Iteration:\t%d\n", iteration);
	printf("  Base64 Salt:\t%s\n", salt_b64);
	printf("  Base64 DK:\t%s\n", dk_b64);
	int i;
	printf("  Stored Salt:\t");
	for(i=0; i<salt_len; i++){
		printf("%02x", salt_value[i]);
	}
	printf("\n");

	printf("  Stored DK:\t");
	for(i=0; i<dk_len; i++){
		printf("%02x", dk_value[i]);
	}
	printf("\n");

	printf("  Input DK:\t");
	for(i=0; i<dk_len; i++){
		printf("%02x", input_dk_value[i]);
	}
	printf("\n");
	printf("  Result:\t%d\n", rc);
#endif
	return rc?LUTIL_PASSWD_ERR:LUTIL_PASSWD_OK;
}

int init_module(int argc, char *argv[]) {
  if (argc > 0) {
    pbkdf2_iteration = atoi(argv[0]);
  }
	return lutil_passwd_add((struct berval *)&pbkdf2_sha256_scheme,
    pbkdf2_check, pbkdf2_encrypt);
}
