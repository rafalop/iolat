// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// start track block device requests
// based on bcc's biolatency
#define DISK_NAME_LEN 16
#define TASK_COMM_LEN 32

struct blk_req_event {
    u8 disk_name[DISK_NAME_LEN];
    u8 comm[TASK_COMM_LEN];
    u32 cmd_flags;
    u64 delta_us;
    u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct request *);
    __type(value, u64);
} blk_req_start_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} blk_req_events SEC(".maps");
//struct {
//	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//    __uint(key_size, sizeof(int));
//    __uint(value_size, sizeof(int));
//	//__uint(max_entries, 1 << 24);
//} blk_req_events SEC(".maps");

// bpf2go seems to need this for generating the object
const struct blk_req_event *unused __attribute__((unused));

// start block I/O
SEC("kprobe/blk_account_io_start")
int BPF_KPROBE(kprobe__blk_account_io_start, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&blk_req_start_times, &req, &ts, 0);
    return 0;
}


// done block I/O
SEC("kprobe/blk_account_io_done")
int kprobe__blk_account_io_done(struct pt_regs *ctx)
//int BPF_KPROBE(kprobe__blk_account_io_done, struct request *req)
{
    u64 *tsp, delta_us;
    //struct blk_req_event d = {};
    //struct blk_req_event *data = &d;
    struct blk_req_event *data;
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);
    tsp = bpf_map_lookup_elem(&blk_req_start_times, &req);
    if (!tsp) {
        return 0;   // missed issue
    }
    delta_us = (bpf_ktime_get_ns() - *tsp)/1000;
    bpf_map_delete_elem(&blk_req_start_times, &req);

    if (delta_us < 50) {
        return 0; // ignore under 50 micro seconds
    }

    data = bpf_ringbuf_reserve(&blk_req_events, sizeof(struct blk_req_event), 0);
    if (!data) {
        return 0; // couldn't reserve
    }

    data->pid = bpf_get_current_pid_tgid();
    data->delta_us = delta_us;
    bpf_core_read(&data->cmd_flags, sizeof(data->cmd_flags), &req->cmd_flags);
    // NOTE req->rq_disk may be removed in later kernels, this was created on jammy kernel
    // https://lore.kernel.org/all/20211126121802.2090656-1-hch@lst.de/
    // https://github.com/iovisor/bcc/issues/3954
    struct gendisk *disk;
    bpf_core_read(&disk, sizeof(disk), &req->rq_disk);
    bpf_probe_read_kernel_str(data->disk_name, sizeof(data->disk_name), disk->disk_name);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    //bpf_perf_event_output(ctx, &blk_req_events, BPF_F_CURRENT_CPU, data, sizeof(*data));
    bpf_ringbuf_submit(data, 0);
    return 0;
}
// end track block device requests
//

// start track vfs requests
// based on bcc's fileslower
#define NAME_MAX 128

enum trace_mode {
    MODE_READ,
    MODE_WRITE
};

struct vfs_data {
    char filename[NAME_MAX];
    u32  io_size;
    u64 ts;
};

struct vfs_io_event {
    enum trace_mode mode;
    u32 pid;
    u32 io_size;
    u64 delta_us;
    //u32 name_len;
    u8 filename[NAME_MAX];
    u8 comm[TASK_COMM_LEN];
};
const struct vfs_io_event *unused_vfs __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct vfs_data);
} vfs_io_recs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} vfs_io_events SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//    __uint(key_size, sizeof(int));
//    __uint(value_size, sizeof(int));
//	//__uint(max_entries, 1 << 24);
//} vfs_io_events SEC(".maps");


static __always_inline int trace_rw_entry(struct file *file, char *buf, size_t count)
{
    struct vfs_data v = {};
    u64 pid = bpf_get_current_pid_tgid();
    u32 name_len = BPF_CORE_READ(file, f_path.dentry, d_name.len);

    // ignore anything without a filename
    if (name_len == 0) 
        return 0;

    v.io_size = count;
    v.ts = bpf_ktime_get_ns();

    // In future we can use bpf_get_file_path() to get full file path
    const unsigned char *name;
    name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(&v.filename, sizeof(v.filename), name);
    //BPF_CORE_READ_STR_INTO(&v.filename, file, f_path.dentry, d_name.name);
    bpf_map_update_elem(&vfs_io_recs, &pid, &v, 0);

    return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe__vfs_read, struct file *file, char *buf, size_t count)
{
    // skip non-sync I/O; see kernel code for __vfs_read()
    if (!(BPF_CORE_READ(file,f_op,read_iter)))
        return 0;
    return trace_rw_entry(file, buf, count);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe__vfs_write, struct file *file, char *buf, size_t count)
{
    // skip non-sync I/O; see kernel code for __vfs_write()
    if (!(BPF_CORE_READ(file,f_op,write_iter)))
        return 0;
    return trace_rw_entry(file, buf, count);
}

// output vfs latency
static __always_inline int trace_rw_return(struct pt_regs *ctx, int type)
{
    struct vfs_data *v;
    //struct vfs_io_event e = {};
    //struct vfs_io_event *event = &e;
    struct vfs_io_event *event;
    u64 pid = bpf_get_current_pid_tgid();

    v = bpf_map_lookup_elem(&vfs_io_recs, &pid);
    if (!v) {
        // missed tracing issue or filtered
        return 0;
    }
    u64 delta_us = (bpf_ktime_get_ns() - v->ts) / 1000;
    if (delta_us < 50) { // ignore ios less than 50 microseconds
            bpf_map_delete_elem(&vfs_io_recs, &pid);
        return 0;
    }

    event = bpf_ringbuf_reserve(&vfs_io_events, sizeof(struct vfs_io_event), 0);
    if (!event) {
        bpf_map_delete_elem(&vfs_io_recs, &pid);
        return 0; // couldn't reserve
    }

    event->mode = type;
    event->pid = pid;
    event->delta_us = delta_us;
    event->io_size = v->io_size;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), v->filename);
    bpf_ringbuf_submit(event, 0);
    //bpf_perf_event_output(ctx, &vfs_io_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&vfs_io_recs, &pid);

    return 0;
}

SEC("kretprobe/vfs_read")
//int BPF_KRETPROBE(kretprobe__vfs_read)
int kretprobe__vfs_read(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, MODE_READ);
}

SEC("kretprobe/vfs_write")
//int BPF_KRETPROBE(kretprobe__vfs_write)
int kretprobe__vfs_write(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, MODE_WRITE);
}
// end track vfs requests
