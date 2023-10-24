package main

import (
	"regexp"
	"flag"
	"bytes"
	"encoding/binary"
	"io"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	//"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// for the below to work, you need to generate the vmlinux.h and point -I below to the directory it lives in. This is done automatically by build.sh
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type blk_req_event -type vfs_io_event -target amd64 -cc clang -cflags "-O2 -g -Wall -Werror" bpf io_latency.c -- -I./


type BlkOp struct {
	Op   string `json:op`
	Sync bool   `json:sync`
}

type BlkLatRec struct {
	Pid    uint32 `json:pid`
	LatUs  uint64 `json:lat_us`
	Device string `json:device`
	Comm   string `json:comm`
	OpInfo BlkOp
}

const (
	REQ_OP_READ  = 0
	REQ_OP_WRITE = 1
	REQ_OP_FLUSH = 2

// REQ_OP_DISCARD = 3,
// REQ_OP_SECURE_ERASE = 5,
// REQ_OP_WRITE_SAME = 7,
// REQ_OP_WRITE_ZEROES = 9,
// REQ_OP_ZONE_OPEN = 10,
// REQ_OP_ZONE_CLOSE = 11,
// REQ_OP_ZONE_FINISH = 12,
// REQ_OP_ZONE_APPEND = 13,
// REQ_OP_ZONE_RESET = 15,
// REQ_OP_ZONE_RESET_ALL = 17,
// REQ_OP_DRV_IN = 34,
// REQ_OP_DRV_OUT = 35,
// REQ_OP_LAST = 36,
// __REQ_FAILFAST_DEV = 8,
// __REQ_FAILFAST_TRANSPORT = 9,
// __REQ_FAILFAST_DRIVER = 10,
)

// request flag bitshifts
// copied from vmlinux.h
const (
	__REQ_SYNC = 11

// __REQ_META = 12,
// __REQ_PRIO = 13,
// __REQ_NOMERGE = 14,
// __REQ_IDLE = 15,
// __REQ_INTEGRITY = 16,
// __REQ_FUA = 17,
// __REQ_PREFLUSH = 18,
// __REQ_RAHEAD = 19,
// __REQ_BACKGROUND = 20,
// __REQ_NOWAIT = 21,
// __REQ_CGROUP_PUNT = 22,
// __REQ_NOUNMAP = 23,
// __REQ_HIPRI = 24,
// __REQ_DRV = 25,
// __REQ_SWAP = 26,
// __REQ_NR_BITS = 27,
)

const (
	REQ_SYNC = 1 << __REQ_SYNC
)

func getOpInfo(b bpfBlkReqEvent) BlkOp {
	var ret BlkOp

	if b.CmdFlags&REQ_OP_WRITE > 0 {
		ret.Op = `write`
	} else if b.CmdFlags&REQ_OP_FLUSH > 0 {
		ret.Op = `flush`
	} else if b.CmdFlags&REQ_OP_READ == 0 {
		ret.Op = `read`
	} else {
		ret.Op = `other`
	}

	if b.CmdFlags&REQ_SYNC > 0 {
		ret.Sync = true
	} else {
		ret.Sync = false
	}

	return ret
}


func getBlkEvent(blkEvent bpfBlkReqEvent) BlkLatRec {
			blkOp := getOpInfo(blkEvent)
			blkRec := BlkLatRec{
				Pid:    blkEvent.Pid,
				LatUs:  blkEvent.DeltaUs,
				Device: unix.ByteSliceToString(blkEvent.DiskName[:]),
				Comm:   unix.ByteSliceToString(blkEvent.Comm[:]),
				OpInfo: blkOp,
			}
	return blkRec
}


func applyStringFilter(s string, filter string) (result bool) {
	result, err := regexp.MatchString(filter, s)
	if err != nil {
		logrus.Printf("regexp error: %s", err)
	}
	//logrus.Printf("checking comm %s against %s  result: %t", s, filter, result)
	return
}

func applyIntFilter(i int, filter int) (result bool) {
	if i == filter || filter == -1{
		result = true
	} else {
		result = false
	}
	//logrus.Printf("checking pid %d against %d  result: %t", i, filter, result)
	return
}

func main() {
	commFilter := flag.String("comm", ".*", "regex string for filtering output by comm")
	pidFilter := flag.Int("pid", -1, "filter by pid")
	blkLatThresh := flag.Int("blkthresh", -1, "latency threshold for blk latency outputs (us)")
	vfsLatThresh := flag.Int("vfsthresh", -1, "latency threshold for vfs latency outputs (us)")
	flag.Parse()
	// Name of the kernel function to trace.

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will emit an event containing pid and command of the execved task.
	//kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	kpBlkIoStart, err := link.Kprobe("blk_account_io_start", objs.KprobeBlkAccountIoStart, nil)
	if err != nil {
		log.Fatalf("Failed to open blk_account_io_start kprobe, err [%s]", err)
	}
	defer kpBlkIoStart.Close()

	kpBlkIoDone, err := link.Kprobe("blk_account_io_done", objs.KprobeBlkAccountIoDone, nil)
	if err != nil {
		log.Fatalf("Failed to open blk_account_io_start kprobe, err [%s]", err)
	}
	defer kpBlkIoDone.Close()

	kpVfsRead, err := link.Kprobe("vfs_read", objs.KprobeVfsRead, nil)
	if err != nil {
		log.Fatalf("Failed to open vfs_read kprobe, err [%s]", err)
	}
	defer kpVfsRead.Close()
	krpVfsRead, err := link.Kretprobe("vfs_read", objs.KretprobeVfsRead, nil)
	if err != nil {
		log.Fatalf("Failed to open vfs_read kretprobe, err [%s]", err)
	}
	defer krpVfsRead.Close()

	kpVfsWrite, err := link.Kprobe("vfs_write", objs.KprobeVfsWrite, nil)
	if err != nil {
		log.Fatalf("Failed to open vfs_write kprobe, err [%s]", err)
	}
	defer kpVfsWrite.Close()
	krpVfsWrite, err := link.Kretprobe("vfs_write", objs.KretprobeVfsWrite, nil)
	if err != nil {
		log.Fatalf("Failed to open vfs_write kretprobe, err [%s]", err)
	}
	defer krpVfsWrite.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	//rd, err := perf.NewReader(objs.BlkReqEvents,10000)
	rd, err := ringbuf.NewReader(objs.BlkReqEvents)
	if err != nil {
		log.Fatalf("error opening blk ringbuf reader: %s", err)
	}
	defer rd.Close()

	rdv, err := ringbuf.NewReader(objs.VfsIoEvents)
	//rdv, err := perf.NewReader(objs.VfsIoEvents, 10000)
	if err != nil {
		log.Fatalf("error opening vfs ringbuf reader: %s", err)
	}
	defer rdv.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing blk perfbuf reader: %s", err)
		}
		if err := rdv.Close(); err != nil {
			log.Fatalf("closing vfs ringbuf reader: %s", err)
		}
		objs.Close()
	}()

	log.Println("Waiting for events..")

	// bpfEvent is generated by bpf2go.
	var event bpfBlkReqEvent
	var vevent bpfVfsIoEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("error reading from blk reader: %s", err)
		} else {
			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			    if err != io.EOF {
                        log.Printf("error parsing buf blk event: %s", err)
			    } 
			} else {
				r := getBlkEvent(event)
				filters := applyStringFilter(r.Comm, *commFilter) && applyIntFilter(int(r.Pid), *pidFilter)
				if filters && int(r.LatUs) > *blkLatThresh {
                			log.Printf("Block latency pid=%d  comm=%s  lat(us)=%d  op=%s  sync=%t  disk=%s\n", r.Pid, r.Comm, r.LatUs, r.OpInfo.Op, r.OpInfo.Sync, r.Device)
				}
			}
		}

		recordv, err := rdv.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("error error reading from vfs reader: %s", err)
		} else {
			if err := binary.Read(bytes.NewBuffer(recordv.RawSample), binary.LittleEndian, &vevent); err != nil {
			    if err != io.EOF {
                        log.Printf("error parsing buf vfs event: %s", err)
			    } 
			} else {
				vcomm := unix.ByteSliceToString(vevent.Comm[:])
				filters := applyStringFilter(vcomm, *commFilter) && applyIntFilter(int(vevent.Pid), *pidFilter)
				vfsOp := "read"
				if vevent.Mode == 1 {
					vfsOp = "write"
				}
			
				if filters && int(vevent.DeltaUs) > *vfsLatThresh {
					log.Printf("VFS latency  pid=%d  comm=%s  lat(us)=%d  op=%s  size=%d  fn=%s", vevent.Pid, unix.ByteSliceToString(vevent.Comm[:]), vevent.DeltaUs, vfsOp, vevent.IoSize, unix.ByteSliceToString(vevent.Filename[:]))
				}
			}
		}

	}
}

