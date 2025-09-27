#!/usr/bin/env bash
set -euo pipefail
KROOT="${1:-.}"

resolve_file() {
  local candidate1="${KROOT}/fs/$1"
  local candidate2="${KROOT}/$1"
  if [[ -f "$candidate1" ]]; then echo "$candidate1"; return 0; fi
  if [[ -f "$candidate2" ]]; then echo "$candidate2"; return 0; fi
  return 1
}

read -r -d '' INC_BLK <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
#include <../drivers/kernelsu/ksu_trace.h>
#endif
EOF

insert_after_line() {
  local file="$1" regex="$2" block="$3"
  if grep -Fq 'drivers/kernelsu/ksu_trace.h' "$file"; then return 0; fi
  awk -v re="$regex" -v block="$block" 'BEGIN{done=0}{print; if(!done && $0 ~ re){print block; done=1}}' "$file" > "$file.__tmp__" && mv "$file.__tmp__" "$file"
}
insert_call_after_line() {
  local file="$1" regex="$2" symbol="$3" block="$4"
  if grep -Fq "$symbol" "$file"; then return 0; fi
  awk -v re="$regex" -v block="$block" 'BEGIN{done=0}{print; if(!done && $0 ~ re){print block; done=1}}' "$file" > "$file.__tmp__" && mv "$file.__tmp__" "$file"
}
backup_once(){ [[ -f "$1.bak" ]] || cp -p "$1" "$1.bak"; }

# exec.c
if EXEC_C="$(resolve_file exec.c)"; then
  backup_once "$EXEC_C"
  insert_after_line "$EXEC_C" '^#include <trace/hooks/sched\.h>' "$INC_BLK"
  read -r -d '' EXEC_HOOK <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_execveat_hook((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif
EOF
  insert_call_after_line "$EXEC_C" 'struct[[:space:]]+user_arg_ptr[[:space:]]+envp[[:space:]]*=' 'trace_ksu_trace_execveat_hook' "$EXEC_HOOK"
  read -r -d '' EXEC_COMPAT_HOOK <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    /* sucompat path (32-bit) */
    trace_ksu_trace_execveat_sucompat_hook((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
#endif
EOF
  insert_call_after_line "$EXEC_C" '^\t\};\s*$' 'trace_ksu_trace_execveat_sucompat_hook' "$EXEC_COMPAT_HOOK"
else
  echo "WARN: exec.c not found" >&2
fi

# open.c
if OPEN_C="$(resolve_file open.c)"; then
  backup_once "$OPEN_C"
  if grep -q '^#include <trace/hooks/syscall_check\.h>' "$OPEN_C"; then
    insert_after_line "$OPEN_C" '^#include <trace/hooks/syscall_check\.h>' "$INC_BLK"
  else
    insert_after_line "$OPEN_C" '^#include "internal\.h"' "$INC_BLK"
  fi
  read -r -d '' FACC_HOOK <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    /* covers faccessat/access/faccessat2 via common helper */
    trace_ksu_trace_faccessat_hook(&dfd, &filename, &mode, NULL);
#endif
EOF
  insert_call_after_line "$OPEN_C" 'const[[:space:]]+struct[[:space:]]+cred[[:space:]]*\*[[:space:]]*old_cred' 'trace_ksu_trace_faccessat_hook' "$FACC_HOOK"
else
  echo "WARN: open.c not found" >&2
fi

# read_write.c
if RW_C="$(resolve_file read_write.c)"; then
  backup_once "$RW_C"
  insert_after_line "$RW_C" '^#include <asm/unistd\.h>' "$INC_BLK"
  if ! grep -Fq 'trace_ksu_trace_sys_read_hook' "$RW_C"; then
    perl -0777 -pe '
      s/(SYSCALL_DEFINE3\(\s*read\s*,[^\)]*\)\s*\{\s*\n)/$1#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)\n    trace_ksu_trace_sys_read_hook(fd, \&buf, \&count);\n#endif\n/s
    ' -i "$RW_C"
  fi
else
  echo "WARN: read_write.c not found" >&2
fi

# stat.c
if STAT_C="$(resolve_file stat.c)"; then
  backup_once "$STAT_C"
  insert_after_line "$STAT_C" '^#include "internal\.h"' "$INC_BLK"
  if ! grep -Fq 'trace_ksu_trace_stat_hook' "$STAT_C"; then
    perl -0777 -pe '
      s/(SYSCALL_DEFINE4\(\s*newfstatat[^\{]*\{\s*\n\s*struct[^\n]*\n\s*int\s+error;\s*\n)/$1#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)\n    trace_ksu_trace_stat_hook(\&dfd, \&filename, \&flag);\n#endif\n/s
    ' -i "$STAT_C"
  fi
else
  echo "WARN: stat.c not found" >&2
fi

echo "Tracepoint hook blocks inserted. Backups: *.bak"
