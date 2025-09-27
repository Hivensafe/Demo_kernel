#!/usr/bin/env bash
# SukiSU tracepoint minimal integration for Linux 6.6
# - CI-safe: no `read -d ''` (which returns 1), no unguarded non-zero exits
# - Idempotent: only inserts once
# - Backups: *.bak next to modified files
set -Eeuo pipefail
trap 'echo "[ERROR] line ${LINENO}: ${BASH_COMMAND}" >&2' ERR

KROOT="${1:-.}"

log() { printf '[%s] %s\n' "$1" "$2"; }

# ---------- text blocks (CI-safe here-doc into variable) ----------
INC_BLK="$(cat <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
#include <../drivers/kernelsu/ksu_trace.h>
#endif
EOF
)"
EXEC_HOOK="$(cat <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_execveat_hook((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif
EOF
)"
EXEC_COMPAT_HOOK="$(cat <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    /* sucompat path (32-bit) */
    trace_ksu_trace_execveat_sucompat_hook((int *)AT_FDCWD, &filename, NULL, NULL, NULL);
#endif
EOF
)"
FACC_HOOK="$(cat <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    /* covers faccessat/access/faccessat2 via common helper */
    trace_ksu_trace_faccessat_hook(&dfd, &filename, &mode, NULL);
#endif
EOF
)"
READ_HOOK="$(cat <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_sys_read_hook(fd, &buf, &count);
#endif
EOF
)"
STAT_HOOK="$(cat <<'EOF'
#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
    trace_ksu_trace_stat_hook(&dfd, &filename, &flag);
#endif
EOF
)"

# ---------- helpers ----------
resolve_file() {
  local f1="${KROOT}/fs/$1" f2="${KROOT}/$1"
  if [[ -f "$f1" ]]; then echo "$f1"; return 0; fi
  if [[ -f "$f2" ]]; then echo "$f2"; return 0; fi
  return 1
}
backup_once() { [[ -f "$1.bak" ]] || cp -p "$1" "$1.bak"; }

insert_after_line() {
  local file="$1" regex="$2" block="$3"
  if grep -Fq 'drivers/kernelsu/ksu_trace.h' "$file"; then
    log OK "include already present in $(basename "$file")"
    return 0
  fi
  if grep -Eq "$regex" "$file"; then
    backup_once "$file"
    awk -v re="$regex" -v block="$block" '
      BEGIN{done=0}
      {print; if(!done && $0 ~ re){print block; done=1}}
    ' "$file" > "$file.__tmp__" && mv "$file.__tmp__" "$file"
    log OK "inserted include into $(basename "$file")"
  else
    log WARN "anchor not found for include in $(basename "$file"); skipped"
  fi
}

insert_call_after_line() {
  local file="$1" regex="$2" symbol="$3" block="$4"
  if grep -Fq "$symbol" "$file"; then
    log OK "$symbol already present in $(basename "$file")"
    return 0
  fi
  if grep -Eq "$regex" "$file"; then
    backup_once "$file"
    awk -v re="$regex" -v block="$block" '
      BEGIN{done=0}
      {print; if(!done && $0 ~ re){print block; done=1}}
    ' "$file" > "$file.__tmp__" && mv "$file.__tmp__" "$file"
    log OK "inserted $symbol in $(basename "$file")"
  else
    log WARN "anchor not found for $symbol in $(basename "$file"); skipped"
  fi
}

perl_replace() {
  local file="$1" pattern="$2" replace="$3" symbol="$4"
  if grep -Fq "$symbol" "$file"; then
    log OK "$symbol already present in $(basename "$file")"
    return 0
  fi
  if perl -v >/dev/null 2>&1; then
    backup_once "$file"
    perl -0777 -pe "$pattern" -i "$file"
    if grep -Fq "$symbol" "$file"; then
      log OK "inserted $symbol in $(basename "$file")"
    else
      log WARN "failed to insert $symbol in $(basename "$file")"
    fi
  else
    log WARN "perl not available; cannot insert $symbol in $(basename "$file")"
  fi
}

# ---------- exec.c ----------
if EXEC_C="$(resolve_file exec.c)"; then
  insert_after_line "$EXEC_C" '^#include <trace/hooks/sched\.h>' "$INC_BLK"
  insert_call_after_line "$EXEC_C" 'struct[[:space:]]+user_arg_ptr[[:space:]]+envp[[:space:]]*=' \
    'trace_ksu_trace_execveat_hook' "$EXEC_HOOK"
  insert_call_after_line "$EXEC_C" '^\t\};\s*$' \
    'trace_ksu_trace_execveat_sucompat_hook' "$EXEC_COMPAT_HOOK"
else
  log WARN "exec.c not found under $KROOT or $KROOT/fs"
fi

# ---------- open.c ----------
if OPEN_C="$(resolve_file open.c)"; then
  if grep -q '^#include <trace/hooks/syscall_check\.h>' "$OPEN_C"; then
    insert_after_line "$OPEN_C" '^#include <trace/hooks/syscall_check\.h>' "$INC_BLK"
  else
    insert_after_line "$OPEN_C" '^#include "internal\.h"' "$INC_BLK"
  fi
  insert_call_after_line "$OPEN_C" 'const[[:space:]]+struct[[:space:]]+cred[[:space:]]*\*[[:space:]]*old_cred' \
    'trace_ksu_trace_faccessat_hook' "$FACC_HOOK"
else
  log WARN "open.c not found under $KROOT or $KROOT/fs"
fi

# ---------- read_write.c ----------
if RW_C="$(resolve_file read_write.c)"; then
  insert_after_line "$RW_C" '^#include <asm/unistd\.h>' "$INC_BLK"
  perl_replace "$RW_C" \
    's/(SYSCALL_DEFINE3\(\s*read\s*,[^\)]*\)\s*\{\s*\n)/$1#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)\n    trace_ksu_trace_sys_read_hook(fd, \&buf, \&count);\n#endif\n/s' \
    'trace_ksu_trace_sys_read_hook' 'trace_ksu_trace_sys_read_hook'
else
  log WARN "read_write.c not found under $KROOT or $KROOT/fs"
fi

# ---------- stat.c ----------
if STAT_C="$(resolve_file stat.c)"; then
  insert_after_line "$STAT_C" '^#include "internal\.h"' "$INC_BLK"
  perl_replace "$STAT_C" \
    's/(SYSCALL_DEFINE4\(\s*newfstatat[^\{]*\{\s*\n\s*struct\s+kstat\s+stat\s*;\s*\n\s*int\s+error\s*;\s*\n)/$1#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)\n    trace_ksu_trace_stat_hook(\&dfd, \&filename, \&flag);\n#endif\n/s' \
    'trace_ksu_trace_stat_hook' 'trace_ksu_trace_stat_hook'
else
  log WARN "stat.c not found under $KROOT or $KROOT/fs"
fi

log DONE "Tracepoint hook integration complete."
