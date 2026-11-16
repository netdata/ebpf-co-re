#define NETDATA_STREAM_BUFFER 1
#define NETDATA_FS_TABLE tbl_btrfs
#define NETDATA_FS_TEMP tmp_btrfs
#define NETDATA_FS_CTRL btrfs_ctrl
#if MY_LINUX_VERSION_CODE < 330240
#define NETDATA_FS_READ_TARGET "generic_file_read_iter"
#define NETDATA_FS_BTRFS_LEGACY_READ 1
#else
#define NETDATA_FS_READ_TARGET "btrfs_file_read_iter"
#endif
#define NETDATA_FS_WRITE_TARGET "btrfs_file_write_iter"
#define NETDATA_FS_OPEN_TARGET "btrfs_file_open"
#define NETDATA_FS_SYNC_TARGET "btrfs_sync_file"
#include "stream_fs_common.bpf.c"
