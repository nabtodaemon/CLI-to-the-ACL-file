# CLI-to-the-ACL-file

This CLI is used to list or alter the contents of the ACL file

To compile:

	gcc unabto_acl.c gopt.c -o unabto_acl

To execute:

	unabto_acl <[list]/[add]/[remove]> -F <acl filename> [-f <fingerprint>] [-u <user>]
	Example: unabto_acl list -F persistence.bin
	         unabto_acl add -F persistence.bin -f a1:0e:...:6f -u mytest
	         unabto_acl remove -F persistence.bin -f a1:0e:...:6f

        options:

            -F <acl filename>: name of the acl binary file 
            -f <figerprint>  : 16 byte device fingerprint as hex string (each byte seperated by ":")
            -u <user>        : name of the device
