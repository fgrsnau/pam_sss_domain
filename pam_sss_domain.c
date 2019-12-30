#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

static const char*
parse_domain(int argc, const char **argv)
{
	static const char *prefix = "domain=";
	for (int i = 0; i < argc; ++i) {
		if (strncmp(argv[i], prefix, strlen(prefix)) == 0) {
			return &argv[i][strlen(prefix)];
		}
	}
	return NULL;
}


PAM_EXTERN int
pam_sm_authenticate(
	pam_handle_t *pamh,
	int flags,
	int argc,
	const char **argv)
{
	const char *old_username;
	pam_get_item(pamh, PAM_USER, (const void**)&old_username);

	if (strstr(old_username, "@")) {
		pam_syslog(pamh, LOG_NOTICE, "username %s already contains fully qualified auth domain, doing nothing", old_username);
		return PAM_SUCCESS;
	}

	const char *domain = parse_domain(argc, argv);
	if (!domain) {
		pam_syslog(pamh, LOG_ERR, "domain= option not specified");
		return PAM_SERVICE_ERR;
	}

	char new_username[LOGIN_NAME_MAX];
	if (snprintf(new_username, sizeof(new_username), "%s@%s", old_username, domain) >= sizeof(new_username)) {
		pam_syslog(pamh, LOG_ERR, "final username larger than LOGIN_NAME_MAX");
		return PAM_SERVICE_ERR;
	}

	if (pam_set_item(pamh, PAM_USER, new_username) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "unable to set PAM_USER to %s", new_username);
		return PAM_SERVICE_ERR;
	}

	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_account_mgmt(
	pam_handle_t *pamh,
	int flags,
	int argc,
	const char **argv)
{
	const char *old_username;
	pam_get_item(pamh, PAM_USER, (const void**)&old_username);

	if (strstr(old_username, "@")) {
		pam_syslog(pamh, LOG_NOTICE, "username %s already contains fully qualified auth domain, doing nothing", old_username);
		return PAM_SUCCESS;
	}

	const char *domain = parse_domain(argc, argv);
	if (!domain) {
		pam_syslog(pamh, LOG_ERR, "domain= option not specified");
		return PAM_SERVICE_ERR;
	}

	char new_username[LOGIN_NAME_MAX];
	if (snprintf(new_username, sizeof(new_username), "%s@%s", old_username, domain) >= sizeof(new_username)) {
		pam_syslog(pamh, LOG_ERR, "final username larger than LOGIN_NAME_MAX");
		return PAM_SERVICE_ERR;
	}

	if (pam_set_item(pamh, PAM_USER, new_username) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "unable to set PAM_USER to %s", new_username);
		return PAM_SERVICE_ERR;
	}

	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_setcred(
	pam_handle_t *pamh,
	int flags,
	int argc,
	const char **argv)
{
	return PAM_CRED_ERR;
}
