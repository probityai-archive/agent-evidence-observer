#!/bin/bash
#SBATCH --job-name=node-checks
#SBATCH --partition=hpg-default
#SBATCH --cpus-per-task=2
#SBATCH --mem=4gb
#SBATCH --time=00:15:00
# Report the compute-node facts an observed agent run depends on: ptrace policy, strace version,
# inotify on the node-local temporary directory, user namespaces, apptainer and the kernel.
# Override the partition on the command line to check a GPU node: submit.sh node_checks.sbatch --partition=hpg-b200 --gres=gpu:b200:1
# Prints one line per check as "CHECK <name> <value>" and exits 1 if the strace version is below the floor.
set -uo pipefail
STRACE_FLOOR=${STRACE_FLOOR:-6.6}
echo "CHECK node $(hostname) job ${SLURM_JOB_ID:-none} date $(date -Is)"
echo "CHECK kernel $(uname -r)"
echo "CHECK tmpdir TMPDIR=${TMPDIR:-unset} SLURM_TMPDIR=${SLURM_TMPDIR:-unset}"
T=${SLURM_TMPDIR:-${TMPDIR:-/tmp}}
echo "CHECK tmpdir_fs $(df -PT "$T" | tail -1 | awk '{print $2" "$1}')"
echo "CHECK ptrace_scope $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)"
echo "CHECK userns_max $(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo unknown)"
echo "CHECK inotify_max_user_watches $(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo unknown)"
echo "CHECK inotify_max_user_instances $(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo unknown)"
SP=$(command -v strace || true)
if [ -n "$SP" ]; then
  SV=$("$SP" --version | head -1 | awk '{print $NF}')
  echo "CHECK strace $SP version $SV"
else
  SV=""
  echo "CHECK strace absent"
fi
echo "CHECK apptainer $(command -v apptainer || echo absent) $(apptainer --version 2>/dev/null || true)"
echo "CHECK setpriv $(command -v setpriv || echo absent)"
# A live ptrace attach under the current policy: trace a child that writes one file.
if [ -n "$SP" ]; then
  W=$(mktemp -d "$T/nodecheck.XXXXXX")
  if "$SP" -f -o "$W/trace.txt" -e trace=openat,write sh -c "echo x > $W/f" 2>"$W/err.txt" && grep -q 'openat' "$W/trace.txt"; then
    echo "CHECK strace_live ok lines $(wc -l < "$W/trace.txt")"
  else
    echo "CHECK strace_live FAILED $(head -c 200 "$W/err.txt")"
  fi
  # inotify on the node-local directory: a create event must arrive.
  python3 - "$W" <<'PY'
import ctypes, ctypes.util, os, select, struct, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
fd = libc.inotify_init1(os.O_NONBLOCK)
if fd < 0:
    print("CHECK inotify FAILED init errno", ctypes.get_errno()); sys.exit(0)
IN_CREATE, IN_MODIFY = 0x100, 0x2
wd = libc.inotify_add_watch(fd, sys.argv[1].encode(), IN_CREATE | IN_MODIFY)
if wd < 0:
    print("CHECK inotify FAILED add_watch errno", ctypes.get_errno()); sys.exit(0)
open(os.path.join(sys.argv[1], "probe"), "w").write("x")
r, _, _ = select.select([fd], [], [], 5)
names = []
if r:
    buf = os.read(fd, 4096)
    off = 0
    while off < len(buf):
        _, mask, _, ln = struct.unpack_from("iIII", buf, off)
        names.append(buf[off + 16: off + 16 + ln].rstrip(b"\0").decode())
        off += 16 + ln
print("CHECK inotify", "ok events for " + ",".join(sorted(set(names))) if names else "FAILED no event in 5 s")
PY
  rm -rf "$W"
fi
if [ -n "$SV" ] && [ "$(printf '%s\n%s\n' "$STRACE_FLOOR" "$SV" | sort -V | head -1)" != "$STRACE_FLOOR" ]; then
  echo "CHECK strace_floor FAILED version $SV is below $STRACE_FLOOR"; exit 1
fi
echo "CHECK strace_floor ok version ${SV:-none} floor $STRACE_FLOOR"
