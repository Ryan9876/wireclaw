//go:build darwin && cgo

package main

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>

static int wireclaw_process_identity(int pid, char *path, int pathSize, long long *seconds, long long *microseconds) {
 struct proc_bsdinfo info;
 memset(&info, 0, sizeof(info));
 int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
 if (count != sizeof(info)) return 0;
 int pathCount = proc_pidpath(pid, path, (uint32_t)pathSize);
 if (pathCount <= 0 || pathCount >= pathSize) return 0;
 *seconds = info.pbi_start_tvsec;
 *microseconds = info.pbi_start_tvusec;
 return 1;
}
*/
import "C"

import (
	"fmt"
)

type processIdentity struct{ started, executable string }

func processIdentityForPID(pid int) (processIdentity, error) {
	if pid <= 0 {
		return processIdentity{}, errProcessIdentity
	}
	path := make([]C.char, C.PROC_PIDPATHINFO_MAXSIZE)
	var seconds, microseconds C.longlong
	if C.wireclaw_process_identity(C.int(pid), &path[0], C.int(len(path)), &seconds, &microseconds) != 1 {
		return processIdentity{}, errProcessIdentity
	}
	return processIdentity{started: fmt.Sprintf("%d:%d", int64(seconds), int64(microseconds)), executable: C.GoString(&path[0])}, nil
}
