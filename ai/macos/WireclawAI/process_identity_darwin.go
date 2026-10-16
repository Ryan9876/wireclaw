//go:build darwin && cgo

package main

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static int wireclaw_pid_absent(int pid) {
 int size = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
 if (size <= 0 || size > 1048576) return 0;
 int capacity = size + 4096;
 int *pids = malloc((size_t)capacity);
 if (!pids) return 0;
 int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, capacity);
 if (bytes <= 0 || bytes >= capacity) { free(pids); return 0; }
 for (int i = 0; i < bytes / (int)sizeof(int); i++) {
  if (pids[i] == pid) { free(pids); return 0; }
 }
 free(pids);
 return 1;
}

static int wireclaw_process_identity(int pid, char *path, int pathSize, long long *seconds, long long *microseconds, int *errorCode) {
 struct proc_bsdinfo info;
 memset(&info, 0, sizeof(info));
 errno = 0;
 int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
 if (count != sizeof(info)) { *errorCode = errno; return 0; }
 int pathCount = proc_pidpath(pid, path, (uint32_t)pathSize);
 if (pathCount <= 0 || pathCount >= pathSize) { *errorCode = errno; return 0; }
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
	var errorCode C.int
	if C.wireclaw_process_identity(C.int(pid), &path[0], C.int(len(path)), &seconds, &microseconds, &errorCode) != 1 {
		if errorCode == C.ESRCH {
			return processIdentity{}, errProcessMissing
		}
		if C.wireclaw_pid_absent(C.int(pid)) == 1 {
			return processIdentity{}, errProcessMissing
		}
		return processIdentity{}, errProcessIdentity
	}
	return processIdentity{started: fmt.Sprintf("%d:%d", int64(seconds), int64(microseconds)), executable: C.GoString(&path[0])}, nil
}
