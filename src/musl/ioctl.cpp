#include <sys/ioctl.h>
#include <posix/fd_map.hpp>

#include "stub.hpp"

static int sys_ioctl(int fd, int req, void* arg) {
  if (fd == 1 or fd == 2) {
    if (req == TIOCGWINSZ) {
      winsize* ws = (winsize*)arg;
      ws->ws_row = 25;
      ws->ws_col = 80;
      return 0;
    }

    if (req == TIOCSWINSZ) {
      const auto* ws = (winsize*) arg;
      (void) ws;
    }

    return 0;
  }

  if(auto* fildes = FD_map::_get(fd); fildes)
    return fildes->ioctl(req, arg);

  return -EBADF;
}

extern "C"
int syscall_SYS_ioctl(int fd, int req, void* arg) {
  return stubtrace(sys_ioctl, "ioctl", fd, req, arg);
}
