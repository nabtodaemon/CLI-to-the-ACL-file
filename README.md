# CLI-to-the-ACL-file

This CLI is used to list or alter the contents of the ACL file

To compile:

        gcc unabto_acl.c -o unabto_acl

To execute:

        unabto_acl <[list]/[add]/[remove]> <ACL file>
        Example: unabto_acl list persistence.bin
                 unabto_acl add persistence.bin
                 unabto_acl remove persistence.bin
