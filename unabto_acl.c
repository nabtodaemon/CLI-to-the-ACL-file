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

#include "unabto_acl.h"

main(argc, argv)
int argc;
char *argv[];
{
    if (argc != 3) {
	printf("Usage: %s <command> <ACL filename>\n", argv[0]);
	exit(1);
    }
    if (strcmp(argv[1],"list") && strcmp(argv[1],"add") && strcmp(argv[1],"remove")) {
	printf("Usage: %s <list/add/remove> <ACL filename>\n", argv[0]);
	exit(1);
    }

    if (!strcmp(argv[1], "list")) {
	if (fp_acl_file_list_file(argv[2]) != FP_ACL_DB_OK)
	    printf("List Failed\n");
    }
    else
    if (!strcmp(argv[1], "remove")) {
	if (fp_acl_file_remove_file(argv[2]) != FP_ACL_DB_OK)
	    printf("Remove Failed\n");
    }
    else
    if (!strcmp(argv[1], "add")) {
	if (fp_acl_file_add_file(argv[2]) != FP_ACL_DB_OK)
	    printf("Add Failed\n");
    }
    else
	printf("Not supported now. Under development\n");
    exit(0);
}

// listing of ACL file
fp_acl_db_status fp_acl_file_list_file(char *filename)
{
    struct fp_mem_state acl;

    FILE* aclFile = fopen(filename, "rb+");
    if (aclFile == NULL) {
        // there no saved acl file, consider it as a completely normal bootstrap scenario
	printf("File [%s] does not exists!\n", filename);
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
fp_acl_db_status fp_acl_file_remove_file(char *filename)
{
    struct fp_mem_state acl;

    FILE* aclFile = fopen(filename, "rb+");
    if (aclFile == NULL) {
        // there no saved acl file, consider it as a completely normal bootstrap scenario
	printf("File [%s] does not exists!\n", filename);
        return FP_ACL_DB_OK;
    }

    memset(&acl, 0, sizeof(struct fp_mem_state));

    fingerprint fp_to_remove;    
    memset(fp_to_remove, 0x20, sizeof(fp_to_remove));

    uint32_t i,j=0;

    fp_get_fp_from_stdin(fp_to_remove);

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
	printf("File [%s] unable to create!\n", filename);
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
    if (rename(tmpFile, filename) != 0) {
        return FP_ACL_DB_SAVE_FAILED;
    }
    printf("Successfully removed\n");
    return FP_ACL_DB_OK;
}

// adding an entry to ACL file
fp_acl_db_status fp_acl_file_add_file(char *filename)
{
    struct fp_mem_state acl;

    FILE* aclFile = fopen(filename, "rb+");
    if (aclFile == NULL) {
        // there no saved acl file, consider it as a completely normal bootstrap scenario
	printf("File [%s] does not exists!\n", filename);
        return FP_ACL_DB_OK;
    }

    memset(&acl, 0, sizeof(struct fp_mem_state));

    fingerprint fp_to_add;    
    username user_to_add;
    memset(fp_to_add, 0x20, sizeof(fp_to_add));

    uint32_t i,j=0;

    fp_get_fp_from_stdin(fp_to_add);
    fp_get_user_from_stdin(&user_to_add);

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
	printf("File [%s] unable to create!\n", filename);
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
    if (rename(tmpFile, filename) != 0) {
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

void fp_get_fp_from_stdin(fingerprint fpLocal)
{
    uint32_t i,j=0;
    char s[48] = "\0";
    while (1) {
        printf("Enter 16Byte Device Fingerprint <eg. 12:ef:50:...:10>: ");
        scanf("%47s", s);
        if (strlen(s) >= 31 || strlen(s) <= 47) { // check length of string 
            for (i=0, j=0; s[i] != '\0'; i++) {
                if (s[i] == ':') j++;
            }
            if (j==15) {	// check number of semicolon in the string
                if (strstr(s,"::") == NULL) {
                    if (s[strspn(s, "0123456789abcdefABCDEF:")] == 0) break; // check for any invalid chars
                }
            }
        }
        printf("Invalid fingerprint. Please retry\n");
    }
    j=0;
    sscanf(s, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", 
	&fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++],
	&fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++], &fpLocal[j++]);

    /*
    for (j=0; j<FP_ACL_FP_LENGTH;j++) 
        printf("%x ", fpLocal[j]);
    */
}

void fp_get_user_from_stdin(username* newUser)
{
    printf("Enter Username: ");
    scanf("%s", newUser);
}
