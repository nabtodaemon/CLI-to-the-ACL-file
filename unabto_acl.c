/************************************************************************************************
* 
* Filename   : unabto_acl.c 
* Description: To add, remove & list ACL file contents
* Usage      : unabto_acl <[add]/[remove]/[list]> <ACL filename>
* Note       : During addition of new users,  by default allow local access and remote access 
*              permissions will be granted.
*              In case, the new user is the first user, then admin access will be granted.
* 
************************************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

struct configuration {
    const char *action;
    const char *aclfilename;
    const char *fingerprint;
    const char *user;
};

#include "unabto_acl.h"
#include "gopt.h"

static void help(const char* errmsg, const char *progname)
{
    if (errmsg) {
        printf("ERROR: %s\n", errmsg);
    }
    printf("Usage: %s <list/add/remove> -F <acl filename> [-f <fingerprint>] [-u <user>]\n\n", progname);
    printf("Example: \n");
    printf("       %s list -F <acl filename>\n", progname);
    printf("       %s add -F <acl filename> -f <fingerprint> -u <user>\n", progname);
    printf("       %s remove -F <acl filename> -f <fingerprint>\n\n", progname);
}

main(argc, argv)
int argc;
char *argv[];
{
    struct configuration config;
    memset(&config, 0, sizeof(struct configuration));

    if (!parse_argv(argc, argv, &config)) {
        help(0, argv[0]);
        return 1;
    }

    if (!strcmp(config.action, "list")) {
	if (fp_acl_file_list_file(&config) != FP_ACL_DB_OK)
	    printf("List Failed\n");
    }
    else
    if (!strcmp(config.action, "remove")) {
	if (fp_acl_file_remove_file(&config) != FP_ACL_DB_OK)
	    printf("Remove Failed\n");
    }
    else
    if (!strcmp(config.action, "add")) {
	if (fp_acl_file_add_file(&config) != FP_ACL_DB_OK)
	    printf("Add Failed\n");
    }

    exit(0);
}

// listing of ACL file
fp_acl_db_status fp_acl_file_list_file(struct configuration* config)
{
    struct fp_mem_state acl;

    FILE* aclFile = fopen(config->aclfilename, "rb+");
    if (aclFile == NULL) {
        // there no saved acl file, consider it as a completely normal bootstrap scenario
	printf("File [%s] does not exists!\n", config->aclfilename);
        return FP_ACL_DB_OK;
    }

    memset(&acl, 0, sizeof(struct fp_mem_state));

    // load version
    uint8_t buffer[128];
    size_t readen = fread(buffer, 4, 1, aclFile);
    if (readen != 1) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    uint32_t version;
    READ_U32(version, buffer);
    if (version != FP_ACL_FILE_VERSION) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    // load system settings
    readen = fread(buffer, 16, 1, aclFile);
    if (readen != 1) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    uint8_t* ptr = buffer;

    uint32_t numUsers;
    uint32_t tmp1, tmp2;
    
    READ_FORWARD_U32(acl.settings.systemPermissions, ptr);
    READ_FORWARD_U32(acl.settings.defaultUserPermissions, ptr);
    READ_FORWARD_U32(acl.settings.firstUserPermissions, ptr);
    READ_FORWARD_U32(numUsers, ptr);

    Convert_2Hex(acl.settings.systemPermissions, &tmp1, &tmp2);
    printf("System Permissions       : %04x:%04x \n", tmp1, tmp2);
    Convert_2Hex(acl.settings.defaultUserPermissions, &tmp1, &tmp2);
    printf("Default User Permissions : %04x:%04x \n", tmp1, tmp2);
    Convert_2Hex(acl.settings.firstUserPermissions, &tmp1, &tmp2);
    printf("First User Permissions   : %04x:%04x \n", tmp1, tmp2);
    printf("Number of users = %d\n", numUsers);

    enum {
        USER_RECORD_SIZE = FP_ACL_FP_LENGTH + FP_ACL_FILE_USERNAME_LENGTH + 4
    };

    uint32_t i,j;
    for(i = 0; i < numUsers && i < FP_MEM_ACL_ENTRIES; i++) {
        readen = fread(buffer, USER_RECORD_SIZE, 1, aclFile);
        if (readen != 1) {
            return FP_ACL_DB_LOAD_FAILED;
        }
        memcpy(acl.users[i].fp, buffer, FP_ACL_FP_LENGTH);
        memcpy(acl.users[i].name, buffer + FP_ACL_FP_LENGTH, FP_ACL_FILE_USERNAME_LENGTH); // guaranteed by compile time check
        READ_U32(acl.users[i].permissions, buffer + FP_ACL_FP_LENGTH + FP_ACL_FILE_USERNAME_LENGTH);

	for (j=0; j<FP_ACL_FP_LENGTH;j++) {
		if (j) printf(":");
		printf("%02x", acl.users[i].fp[j]);
	}
        Convert_2Hex(acl.users[i].permissions, &tmp1, &tmp2);
	printf("  %04x:%04x  %s\n", tmp1, tmp2, acl.users[i].name);
    }

    return FP_ACL_DB_OK;
}

// removing an entry from ACL file
fp_acl_db_status fp_acl_file_remove_file(struct configuration* config)
{
    struct fp_mem_state acl;
    char *tmp_fp;

    FILE* aclFile = fopen(config->aclfilename, "rb+");
    if (aclFile == NULL) {
        // there no saved acl file, consider it as a completely normal bootstrap scenario
	printf("File [%s] does not exists!\n", config->aclfilename);
        return FP_ACL_DB_OK;
    }

    memset(&acl, 0, sizeof(struct fp_mem_state));

    fingerprint fp_to_remove;    
    memset(fp_to_remove, 0x20, sizeof(fp_to_remove));

    uint32_t i,j=0;

    tmp_fp = strdup(config->fingerprint);
    if (fp_get_fingerprint(tmp_fp, fp_to_remove) != 1) {
        printf("Invalid Fingerprint\n");
        return FP_ACL_DB_LOAD_FAILED;
    }

    // load version
    uint8_t buffer[128];
    uint8_t* ptr1 = buffer;
    size_t readen = fread(buffer, 4, 1, aclFile);
    if (readen != 1) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    uint32_t version;
    READ_U32(version, buffer);
    if (version != FP_ACL_FILE_VERSION) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    // load system settings
    readen = fread(buffer, 16, 1, aclFile);
    if (readen != 1) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    uint8_t* ptr = buffer;
    uint32_t numUsers;

    READ_FORWARD_U32(acl.settings.systemPermissions, ptr);
    READ_FORWARD_U32(acl.settings.defaultUserPermissions, ptr);
    READ_FORWARD_U32(acl.settings.firstUserPermissions, ptr);
    READ_FORWARD_U32(numUsers, ptr);

    enum {
        USER_RECORD_SIZE = FP_ACL_FP_LENGTH + FP_ACL_FILE_USERNAME_LENGTH + 4
    };

    for(i = 0, j=0; i < numUsers && i < FP_MEM_ACL_ENTRIES; i++) {
        readen = fread(buffer, USER_RECORD_SIZE, 1, aclFile);
        if (readen != 1) {
            return FP_ACL_DB_LOAD_FAILED;
        }
        memcpy(acl.users[j].fp, buffer, FP_ACL_FP_LENGTH);

	if (!memcmp(acl.users[j].fp, fp_to_remove, FP_ACL_FP_LENGTH))
		continue;	/* skip this user - to be removed */

        memcpy(acl.users[j].name, buffer + FP_ACL_FP_LENGTH, FP_ACL_FILE_USERNAME_LENGTH); // guaranteed by compile time check
        READ_U32(acl.users[j++].permissions, buffer + FP_ACL_FP_LENGTH + FP_ACL_FILE_USERNAME_LENGTH);
    }
    if (numUsers == j) {
        printf("No matching fingerprint found.\n");
        return FP_ACL_DB_OK;
    }
    numUsers = j;

    char *tmpFile = "acl_tmp.bin";
    FILE* aclFileTmp = fopen(tmpFile, "wb");
    if (aclFileTmp == NULL) {
	printf("Unable to create temp file!\n");
        return FP_ACL_DB_OK;
    }

    WRITE_FORWARD_U32(ptr1, FP_ACL_FILE_VERSION);
    WRITE_FORWARD_U32(ptr1, acl.settings.systemPermissions);
    WRITE_FORWARD_U32(ptr1, acl.settings.defaultUserPermissions);
    WRITE_FORWARD_U32(ptr1, acl.settings.firstUserPermissions);
    WRITE_FORWARD_U32(ptr1, numUsers);

    size_t written = fwrite(buffer, 20, 1, aclFileTmp);
    if (written != 1) {
        return FP_ACL_DB_SAVE_FAILED;
    }

    // write user records
    for (i = 0; i < numUsers; i++) {
        struct fp_acl_user* it = &acl.users[i];
        if (!fp_mem_is_slot_free(it)) {
            memcpy(buffer, it->fp, 16);
            memcpy(buffer+16, it->name, 64);
            WRITE_U32(buffer + 16 + 64, it->permissions);
            written = fwrite(buffer, 84, 1, aclFileTmp);
            if (written != 1) {
                return FP_ACL_DB_SAVE_FAILED;
            }
        }
    }
    fflush(aclFileTmp);
    fclose(aclFileTmp);
    if (rename(tmpFile, config->aclfilename) != 0) {
        return FP_ACL_DB_SAVE_FAILED;
    }
    printf("Successfully removed\n");
    return FP_ACL_DB_OK;
}

// adding an entry to ACL file
fp_acl_db_status fp_acl_file_add_file(struct configuration* config)
{
    struct fp_mem_state acl;
    char *tmp_fp;

    FILE* aclFile = fopen(config->aclfilename, "rb+");
    if (aclFile == NULL) {
        // there no saved acl file, consider it as a completely normal bootstrap scenario
	printf("File [%s] does not exists!\n", config->aclfilename);
        return FP_ACL_DB_OK;
    }

    memset(&acl, 0, sizeof(struct fp_mem_state));

    fingerprint fp_to_add;    
    username user_to_add;
    memset(fp_to_add, 0x20, sizeof(fp_to_add));

    uint32_t i,j=0;

    tmp_fp = strdup(config->fingerprint);
    if (fp_get_fingerprint(tmp_fp, fp_to_add) != 1) {
        printf("Invalid Fingerprint\n");
        return FP_ACL_DB_LOAD_FAILED;
    }
    memcpy(user_to_add, config->user, FP_ACL_USERNAME_MAX_LENGTH);

    // load version
    uint8_t buffer[128];
    uint8_t* ptr1 = buffer;
    size_t readen = fread(buffer, 4, 1, aclFile);
    if (readen != 1) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    uint32_t version;
    READ_U32(version, buffer);
    if (version != FP_ACL_FILE_VERSION) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    // load system settings
    readen = fread(buffer, 16, 1, aclFile);
    if (readen != 1) {
        return FP_ACL_DB_LOAD_FAILED;
    }

    uint8_t* ptr = buffer;
    uint32_t numUsers;

    READ_FORWARD_U32(acl.settings.systemPermissions, ptr);
    READ_FORWARD_U32(acl.settings.defaultUserPermissions, ptr);
    READ_FORWARD_U32(acl.settings.firstUserPermissions, ptr);
    READ_FORWARD_U32(numUsers, ptr);

    enum {
        USER_RECORD_SIZE = FP_ACL_FP_LENGTH + FP_ACL_FILE_USERNAME_LENGTH + 4
    };

    for(i = 0; i < numUsers && i < FP_MEM_ACL_ENTRIES; i++) {
        readen = fread(buffer, USER_RECORD_SIZE, 1, aclFile);
        if (readen != 1) {
            return FP_ACL_DB_LOAD_FAILED;
        }
        memcpy(acl.users[i].fp, buffer, FP_ACL_FP_LENGTH);

	if (!memcmp(acl.users[i].fp, fp_to_add, FP_ACL_FP_LENGTH)) {
            printf("FP already exists.\n");
            return FP_ACL_DB_LOAD_FAILED;
        }

        memcpy(acl.users[i].name, buffer + FP_ACL_FP_LENGTH, FP_ACL_FILE_USERNAME_LENGTH); // guaranteed by compile time check
        READ_U32(acl.users[i].permissions, buffer + FP_ACL_FP_LENGTH + FP_ACL_FILE_USERNAME_LENGTH);
    }

    char *tmpFile = "acl_tmp.bin";
    FILE* aclFileTmp = fopen(tmpFile, "wb");
    if (aclFileTmp == NULL) {
	printf("Unable to create temp file!\n");
        return FP_ACL_DB_OK;
    }

    // add new user to acl
    uint32_t permissions_to_add;
    memcpy(acl.users[numUsers].fp, fp_to_add, FP_ACL_FP_LENGTH);
    memcpy(acl.users[numUsers].name, user_to_add, FP_ACL_FILE_USERNAME_LENGTH);
    if (numUsers == 0) 
        permissions_to_add = FP_ACL_PERMISSION_ADMIN | FP_ACL_PERMISSION_REMOTE_ACCESS | FP_ACL_PERMISSION_LOCAL_ACCESS;
    else
        permissions_to_add = FP_ACL_PERMISSION_REMOTE_ACCESS | FP_ACL_PERMISSION_LOCAL_ACCESS;
    acl.users[numUsers].permissions = permissions_to_add;

    numUsers++;  // increment number of users
    WRITE_FORWARD_U32(ptr1, FP_ACL_FILE_VERSION);
    WRITE_FORWARD_U32(ptr1, acl.settings.systemPermissions);
    WRITE_FORWARD_U32(ptr1, acl.settings.defaultUserPermissions);
    WRITE_FORWARD_U32(ptr1, acl.settings.firstUserPermissions);
    WRITE_FORWARD_U32(ptr1, numUsers);

    size_t written = fwrite(buffer, 20, 1, aclFileTmp);
    if (written != 1) {
        return FP_ACL_DB_SAVE_FAILED;
    }

    // write user records
    for (i = 0; i < numUsers; i++) {
        struct fp_acl_user* it = &acl.users[i];
        if (!fp_mem_is_slot_free(it)) {
            memcpy(buffer, it->fp, 16);
            memcpy(buffer+16, it->name, 64);
            WRITE_U32(buffer + 16 + 64, it->permissions);
            written = fwrite(buffer, 84, 1, aclFileTmp);
            if (written != 1) {
                return FP_ACL_DB_SAVE_FAILED;
            }
        }
    }
    fflush(aclFileTmp);
    fclose(aclFileTmp);
    if (rename(tmpFile, config->aclfilename) != 0) {
        return FP_ACL_DB_SAVE_FAILED;
    }
    printf("Successfully added\n");
}

bool fp_mem_is_slot_free(struct fp_acl_user* ix)
{
    fingerprint emptyFp;
    memset(emptyFp, 0, sizeof(fingerprint));
    bool fpIsEmpty = (memcmp(ix->fp, emptyFp, sizeof(fingerprint)) == 0);
    return fpIsEmpty;
}

void Convert_2Hex(uint32_t val, uint32_t *tmp1, uint32_t *tmp2) 
{
    *tmp1 = val; *tmp1 >>= 16;
    *tmp2 = val & 0xffff;
}

bool fp_get_fingerprint(char *fpargv, fingerprint fpLocal)
{
    uint32_t i,j = 0;

    if (strlen(fpargv) >= 31 || strlen(fpargv) <= 47) { // check length of string 
        for (i=0, j=0; fpargv[i] != '\0'; i++) {
            if (fpargv[i] == ':') j++;
        }
        i = 0;
        if (j==15) {	// check number of semicolon in the string
            if (strstr(fpargv,"::") == NULL) {
                if (fpargv[strspn(fpargv, "0123456789abcdefABCDEF:")] == 0)   // check for any invalid chars
                    i = 1; 
            }
        }
    }
    if (!i) {
        return false;
    }

    j=0;
    sscanf(fpargv, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", 
	&fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++],
	&fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++]);

    /*
    for (j=0; j<FP_ACL_FP_LENGTH;j++) 
        printf("%x ", fpLocal[j]);
    */

    return true;
}

bool parse_argv(int argc, char* argv[], struct configuration* config) 
{
    const char x0s[] = "h?";     const char* x0l[] = { "help", 0 };
    const char x1s[] = "F";      const char* x1l[] = { "aclfilename", 0 };
    const char x2s[] = "f";      const char* x2l[] = { "fingerprint", 0 };
    const char x3s[] = "u";      const char* x3l[] = { "user", 0 };

    const struct { int k; int f; const char *s; const char*const* l; } opts[] = {
        { 'h', 0,           x0s, x0l },
        { 'F', GOPT_ARG,    x1s, x1l },
        { 'f', GOPT_ARG,    x2s, x2l },
        { 'u', GOPT_ARG,    x3s, x3l },
        { 0, 0, 0, 0 }
    };
    void *options = gopt_sort( & argc, (const char**)argv, opts);

    if( gopt( options, 'h')) {
        help(0, argv[0]);
        exit(0);
    }

    if (argc <= 1) return false;
    config->action = strdup(argv[1]);
    if (strcmp(config->action, "list") && strcmp(config->action, "add") && strcmp(config->action, "remove")) {
       	    return false;
    }

    if (!gopt_arg(options, 'F', &config->aclfilename)) {
        return false;
    }

    if (!strcmp(config->action, "add") || !strcmp(config->action, "remove")) {
        if (!gopt_arg(options, 'f', &config->fingerprint)) {
            return false;
        }
    }

    if (!strcmp(config->action, "add")) {
        if (!gopt_arg(options, 'u', &config->user)) {
            return false;
        }
    }

    return true;
}
