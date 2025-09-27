#!/usr/bin/env bash
set -euo pipefail

KROOT="${1:-.}"

inc_block='#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
#include <../drivers/kernelsu/ksu_trace.h>
#endif'

log(){ printf '[%s] %s\n' "$1" "$2"; }

insert_after(){ # file regex block
  local f="$1" re="$2" blk="$3"
  if grep -Fq 'drivers/kernelsu/ksu_trace.h' "$f"; then
    log OK "$(basename "$f"): include already present"; return
  fi
  if grep -Eq "$re" "$f"; then
    awk -v R="$re" -v B="$blk" '
      BEGIN{done=0}
      {print; if(!done && $0 ~ R){print B; done=1}}
    ' "$f" > "$f.__tmp__" && mv "$f.__tmp__" "$f"
    log OK "$(basename "$f"): inserted include"
  else
    log WARN "$(basename "$f"): include anchor not found; skipped"
  fi
}

insert_call_after(){ # file regex symbol block
  local f="$1" re="$2" sym="$3" blk="$4"
  if grep -Fq "$sym" "$f"; then
    log OK "$(basename "$f"): $sym already present"; return
  fi
  if grep -Eq "$re" "$f"; then
    awk -v R="$re" -v B="$blk" '
      BEGIN{done=0}
      {print; if(!done && $0 ~ R){print B; done=1}}
    ' "$f" > "$f.__tmp__" && mv "$f.__tmp__" "$f"
    log OK "$(basename "$f"): inserted $sym"
  else
    log WARN "$(basename "$f"): anchor for $sym not found; skipped"
  fi
}

# ---------- exec.c ----------
EXEC_C="$KROOT/fs/exec.c"
if [ -f "$EXEC_C" ]; then
  insert_after "$EXEC_C" '^#include <trace/hooks/sched[.]h>' "$inc_block"

  exec_hook='#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_execveat_hook((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif'
  insert_call_after "$EXEC_C" 'struct[[:space:]]+user_arg_ptr[[:space:]]+envp[[:space:]]*=' \
    'trace_ksu_trace_execveat_hook' "$exec_hook"

  # sucompat 可选（某些 6.6 分支没有 compat），找不到就跳过
  compat_hook='#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_execveat_sucompat_hook((int *)AT_FDCWD, &filename, NULL, NULL, NULL); /* 32-bit su */
#endif'
  insert_call_after "$EXEC_C" 'static[[:space:]]+int[[:space:]]+compat_do_execve(at)?[[:space:]]*\(' \
    'trace_ksu_trace_execveat_sucompat_hook' "$compat_hook"
else
  log WARN "fs/exec.c not found"
fi

# ---------- open.c ----------
OPEN_C="$KROOT/fs/open.c"
if [ -f "$OPEN_C" ]; then
  if grep -Eq '^#include <trace/hooks/syscall_check[.]h>' "$OPEN_C"; then
    insert_after "$OPEN_C" '^#include <trace/hooks/syscall_check[.]h>' "$inc_block"
  else
    insert_after "$OPEN_C" '^#include "internal[.]h"' "$inc_block"
  fi

  facc_hook='#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_faccessat_hook(&dfd, &filename, &mode, NULL);
#endif'
  insert_call_after "$OPEN_C" 'const[[:space:]]+struct[[:space:]]+cred[[:space:]]*\*[[:space:]]*old_cred' \
    'trace_ksu_trace_faccessat_hook' "$facc_hook"
else
  log WARN "fs/open.c not found"
fi

# ---------- read_write.c ----------
RW_C="$KROOT/fs/read_write.c"
if [ -f "$RW_C" ]; then
  insert_after "$RW_C" '^#include <asm/unistd[.]h>' "$inc_block"

  # 在 SYSCALL_DEFINE3(read, ...) 的函数体首行插入
  if ! grep -Fq 'trace_ksu_trace_sys_read_hook' "$RW_C"; then
    awk '
      BEGIN{state=0}
      {
        print
        if(state==0 && $0 ~ /SYSCALL_DEFINE3[[:space:]]*\([[:space:]]*read[[:space:]]*,/){ state=1; next }
        if(state==1 && $0 ~ /^{/){
          print "#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)"
          print "    trace_ksu_trace_sys_read_hook(fd, &buf, &count);"
          print "#endif"
          state=2
        }
      }' "$RW_C" > "$RW_C.__tmp__" && mv "$RW_C.__tmp__" "$RW_C"
    log OK "read_write.c: inserted trace_ksu_trace_sys_read_hook"
  else
    log OK "read_write.c: trace_ksu_trace_sys_read_hook already present"
  fi
else
  log WARN "fs/read_write.c not found"
fi

# ---------- stat.c ----------
STAT_C="$KROOT/fs/stat.c"
if [ -f "$STAT_C" ]; then
  insert_after "$STAT_C" '^#include "internal[.]h"' "$inc_block"

  stat_hook='#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_stat_hook(&dfd, &filename, &flag);
#endif'
  # 在 newfstatat() 的 "int error;" 之后插入
  insert_call_after "$STAT_C" 'SYSCALL_DEFINE4[[:space:]]*\([[:space:]]*newfstatat[[:space:]]*,[^\{]*\{[[:space:]]*$' \
    'trace_ksu_trace_stat_hook' "$stat_hook"
  # 如上锚点有偏差，补一个更宽松的：
  insert_call_after "$STAT_C" 'struct[[:space:]]+kstat[[:space:]]+stat;[[:space:]]*$' \
    'trace_ksu_trace_stat_hook' "$stat_hook"
else
  log WARN "fs/stat.c not found"
fi

log DONE "tracepoint minimal integration complete"
