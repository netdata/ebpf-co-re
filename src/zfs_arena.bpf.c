#define NETDATA_STREAM_ARENA 1
#define NETDATA_FS_TABLE tbl_zfs
#define NETDATA_FS_TEMP tmp_zfs
#define NETDATA_FS_CTRL zfs_ctrl
#define NETDATA_FS_READ_TARGET "zpl_iter_read"
#define NETDATA_FS_WRITE_TARGET "zpl_iter_write"
#define NETDATA_FS_OPEN_TARGET "zpl_open"
#define NETDATA_FS_SYNC_TARGET "zpl_fsync"
#include "stream_fs_common.bpf.c"
