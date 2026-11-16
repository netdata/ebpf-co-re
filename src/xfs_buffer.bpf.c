#define NETDATA_STREAM_BUFFER 1
#define NETDATA_FS_TABLE tbl_xfs
#define NETDATA_FS_TEMP tmp_xfs
#define NETDATA_FS_CTRL xfs_ctrl
#define NETDATA_FS_READ_TARGET "xfs_file_read_iter"
#define NETDATA_FS_WRITE_TARGET "xfs_file_write_iter"
#define NETDATA_FS_OPEN_TARGET "xfs_file_open"
#define NETDATA_FS_SYNC_TARGET "xfs_file_fsync"
#include "stream_fs_common.bpf.c"
