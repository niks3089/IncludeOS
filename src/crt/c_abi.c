// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <kprint>
#define HEAP_ALIGNMENT   63

void* __dso_handle;

uint32_t _move_symbols(void* sym_loc)
{
  extern char _ELF_SYM_START_;
  /// read out size of symbols **before** moving them
  extern int  _get_elf_section_datasize(const void*);
  int elfsym_size = _get_elf_section_datasize(&_ELF_SYM_START_);
  elfsym_size = (elfsym_size < HEAP_ALIGNMENT) ? HEAP_ALIGNMENT : elfsym_size;

  /// move ELF symbols to safe area
  extern void _move_elf_syms_location(const void*, void*);
  _move_elf_syms_location(&_ELF_SYM_START_, sym_loc);

  return elfsym_size;
}

void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen)
{
  assert (len <= destlen);
  return memcpy(dest, src, len);
}
void* __memset_chk(void* dest, int c, size_t len, size_t destlen)
{
  assert (len <= destlen);
  return memset(dest, c, len);
}
char* __strcat_chk(char* dest, const char* src, size_t destlen)
{
  size_t len = strlen(dest) + strlen(src) + 1;
  assert (len <= destlen);
  return strcat(dest, src);
}

__attribute__((format(printf, 2, 3)))
int __printf_chk (int flag, const char *format, ...)
{
  (void) flag;
  va_list ap;
  va_start (ap, format);
  int done = vfprintf (stdout, format, ap);
  va_end (ap);
  return done;
}
int __fprintf_chk(FILE* fp, int flag, const char* format, ...)
{
  (void) flag;
  va_list arg;
  va_start (arg, format);
  int done = vfprintf(fp, format, arg);
  va_end (arg);
  return done;
}
int __vfprintf_chk(FILE* fp, int flag, const char *format, va_list ap)
{
  (void) flag;
  int done;
  done = vfprintf (fp, format, ap);
  return done;
}
int __vsprintf_chk(char* s, int flag, size_t slen, const char* format, va_list args)
{
  (void) flag;
  int res = vsnprintf(s, slen, format, args);
  assert ((size_t) res < slen);
  return res;
}
__attribute__((format(printf, 4, 5)))
int __sprintf_chk(char* s, int flags, size_t slen, const char *format, ...)
{
  va_list arg;
  int done;
  va_start (arg, format);
  done = __vsprintf_chk(s, flags, slen, format, arg);
  va_end (arg);
  return done;
}

int __isoc99_scanf (const char *format, ...)
{
  va_list arg;
  va_start (arg, format);
  int done = vfscanf(stdin, format, arg);
  va_end (arg);
  return done;
}
__attribute__((format(scanf, 2, 3)))
int __isoc99_sscanf (const char *s, const char *format, ...)
{
  va_list arg;
  int done;
  va_start (arg, format);
  done = vsscanf(s, format, arg);
  va_end (arg);
  return done;
}
