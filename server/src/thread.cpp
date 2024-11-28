#include "include/thread.h"

#include <cstdio>

#include <sys/syscall.h>

namespace CurrentThread {
__thread int t_cachedTid = 0;
__thread char t_tidString[32];
__thread const char *t_threadName = "unknown";

void cacheTid() {
  if (t_cachedTid == 0) {
    t_cachedTid = gettid();
    snprintf(t_tidString, sizeof(t_tidString), "%5d ", t_cachedTid);
  }
}

int tid() {
  if (t_cachedTid == 0) {
    cacheTid();
  }
  return t_cachedTid;
}

bool isMainThread() {
  return tid() == ::gettid();
}

const char *tidString() {
  return t_tidString;
}

pid_t gettid() {
  return static_cast<pid_t>(::syscall(SYS_gettid));
}

} // namespace CurrentThread
