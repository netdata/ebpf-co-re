#define NETDATA_STREAM_BUFFER 1
#define NETDATA_FS_TABLE tbl_nfs
#define NETDATA_FS_TEMP tmp_nfs
#define NETDATA_FS_CTRL nfs_ctrl
#define NETDATA_FS_READ_TARGET "nfs_file_read"
#define NETDATA_FS_WRITE_TARGET "nfs_file_write"
#define NETDATA_FS_OPEN_TARGET "nfs_file_open"
#define NETDATA_FS_SYNC_TARGET "nfs_getattr"
#define NETDATA_FS_EXTRA_OPEN_TARGET "nfs4_file_open"
#include "stream_fs_common.bpf.c"
