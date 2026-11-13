#define NETDATA_STREAM_BUFFER 1
#define NETDATA_FS_TABLE tbl_ext4
#define NETDATA_FS_TEMP tmp_ext4
#define NETDATA_FS_CTRL ext4_ctrl
#define NETDATA_FS_READ_TARGET "ext4_file_read_iter"
#define NETDATA_FS_WRITE_TARGET "ext4_file_write_iter"
#define NETDATA_FS_OPEN_TARGET "ext4_file_open"
#define NETDATA_FS_SYNC_TARGET "ext4_sync_file"
#include "stream_fs_common.bpf.c"
