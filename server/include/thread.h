#pragma once

#include <unistd.h>

#include <sys/syscall.h>
#include <sys/types.h>

namespace CurrentThread {

extern __thread int t_cachedTid;
void cacheTid();
int tid();

bool isMainThread();
const char *tidString();
pid_t gettid();
} // namespace CurrentThread
