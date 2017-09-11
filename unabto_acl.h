/* unabto_acl.h */

/* fp_acl.h */
#define FP_ACL_FP_LENGTH 16
#define FP_ACL_USERNAME_MAX_LENGTH 64

/* fp_acl_memory.h */
#define FP_MEM_ACL_ENTRIES 32

/* fp_acl_file.h */
#define FP_ACL_FILE_USERNAME_LENGTH 64
#define FP_ACL_FILE_VERSION 2

/* fp_acl.h */
#define FP_ACL_PERMISSION_LOCAL_ACCESS                              0x80000000ul
#define FP_ACL_PERMISSION_REMOTE_ACCESS                             0x40000000ul
#define FP_ACL_PERMISSION_ADMIN                                     0x20000000ul

typedef uint8_t fingerprint[FP_ACL_FP_LENGTH];
typedef char username[FP_ACL_USERNAME_MAX_LENGTH];

struct fp_acl_user {
    fingerprint fp;
    username name;
    uint32_t permissions;
};

struct fp_acl_settings {
    uint32_t systemPermissions;      ///< permission bits controlling the system
    uint32_t defaultUserPermissions; ///< default permissions for new users
    uint32_t firstUserPermissions;   ///< permissions to give the first user of the system
};

typedef enum {
    FP_ACL_DB_OK,
    FP_ACL_DB_FULL,
    FP_ACL_DB_SAVE_FAILED,
    FP_ACL_DB_LOAD_FAILED,
    FP_ACL_DB_FAILED
} fp_acl_db_status;

/* fp_acl_memory.h */
struct fp_mem_state {
    struct fp_acl_settings settings;
    struct fp_acl_user users[FP_MEM_ACL_ENTRIES];    
};

/* unabto_util.h */
#ifndef READ_U32
/**
 * Read an unsigned 4-byte integer in network byte order.
 * @param u32  the integer.
 * @param src  source address
 * @return
 */
#define READ_U32(u32, src) do {            \
    uint8_t* src8 = (uint8_t*)(src);       \
    (u32) = (((uint32_t)src8[0]) << 24) |  \
            (((uint32_t)src8[1]) << 16) |  \
            (((uint32_t)src8[2]) <<  8) |  \
            ( (uint32_t)src8[3]       );   \
} while (0)
#endif
#ifndef WRITE_U32
/**
 * Write an unsigned 4-byte integer to network byte order.
 * @param dst  destination address.
 * @param u32  the integer
 * @return
 */
#define WRITE_U32(dst, u32) do {                \
    uint8_t* dst8 = (uint8_t*)(dst);            \
    dst8[0] = (uint8_t)(((uint32_t)(u32) >> 24) & 0xff);  \
    dst8[1] = (uint8_t)(((uint32_t)(u32) >> 16) & 0xff);  \
    dst8[2] = (uint8_t)(((uint32_t)(u32) >>  8) & 0xff);  \
    dst8[3] = (uint8_t)( (uint32_t)(u32)        & 0xff);  \
} while (0);
#endif

#define READ_FORWARD_U32(value, pointer) do { READ_U32(value, pointer); pointer += 4; } while(0)
#define WRITE_FORWARD_U32(pointer, value) do { WRITE_U32(pointer, value); pointer += 4; } while (0)


/* Function Prototypes */
fp_acl_db_status fp_acl_file_list_file();
fp_acl_db_status fp_acl_file_remove_file();
fp_acl_db_status fp_acl_file_add_file();
bool fp_mem_is_slot_free(struct fp_acl_user* ix);
bool parse_argv(int argc, char* argv[], struct configuration* config);
static void help(const char* errmsg, const char *progname);
void Convert_2Hex(uint32_t val, uint32_t *tmp1, uint32_t *tmp2);
bool fp_get_fingerprint(char *, fingerprint fpLocal);
