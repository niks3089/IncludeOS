// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2018 IncludeOS AS, Oslo, Norway
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <arch/x86/cpu.hpp>
#include <os>

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004


#ifdef __x86_64__
int __arch_prctl(int code, uintptr_t ptr){

  switch(code){
  case ARCH_SET_GS:
    kprintf("<arch_prctl> set_gs to %#lx\n", ptr);
    if (!ptr) return -1;
    x86::CPU::set_gs((void*)ptr);
    break;
  case ARCH_SET_FS:
    kprintf("<arch_prctl> set_fs to %#lx\n", ptr);
    if (!ptr) return -1;
    x86::CPU::set_fs((void*)ptr);
    break;
  case ARCH_GET_GS:
    panic("<arch_prctl> get gs \n");
    break;
  case ARCH_GET_FS:
    panic("<arch_prctl> get gs \n");
    break;
  }
  return 0;
}
#endif

extern "C"
uintptr_t syscall_entry(uint64_t n, uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5)
{
  kprintf("<syscall entry> no %lu (a1=%#lx a2=%#lx a3=%#lx a4=%#lx a5=%#lx) \n",
          n, a1, a2, a3, a4, a5);

  switch(n) {
  case 158: // arch_prctl
    __arch_prctl(a1, a2);
    break;
  }
  return 0;
}
