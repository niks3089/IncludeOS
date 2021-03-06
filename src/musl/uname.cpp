#include "common.hpp"
#include <sys/utsname.h>
#include <kernel/os.hpp>

static long sys_uname(struct utsname *buf) {
  if(UNLIKELY(buf == nullptr))
    return -EFAULT;

  strcpy(buf->sysname, "IncludeOS");

  strcpy(buf->nodename, "IncludeOS-node");

  strcpy(buf->release, OS::version().c_str());

  strcpy(buf->version, OS::version().c_str());

  strcpy(buf->machine, ARCH);

  return 0;
}

extern "C"
long syscall_SYS_uname(struct utsname *buf) {
  return strace(sys_uname, "uname", buf);
}
