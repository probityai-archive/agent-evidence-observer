# Agent launcher: technical reference

The worked example is [What did the agent run and change?](../AGENT-LAUNCHER.md).
This page holds the commands, the run directory, the record fields and the
limits.

## Commands

From a checkout, with Python 3.12 and docker (start directory: the repository
root):

```sh
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -e '.[test]'
docker build -t probity-observer-agent-test:local tests/launch/image
.venv/bin/agent-evidence-observer launch-agent ./agent-run \
  --backend docker --image probity-observer-agent-test:local \
  --workspace ./my-workspace --claim-id task-1 --invocation-id call-1 \
  -- python3 -m unittest discover -s tests -t .
```

The command prints `agentExit`, `coverage`, `launchSha256` and `witnessScope`
and exits 0 when the launch itself ran, whatever the agent did. The run
directory must be empty. `--env KEY=VALUE` passes an environment variable,
`--network` allows network (each `connect` is recorded), and `--timeout`
bounds the run in seconds.

On a Slurm node with apptainer, build a SIF from the same image
(`apptainer build agent.sif docker-archive://agent-img.tar`), put the
workspace on node-local scratch (`$TMPDIR` on HiPerGator; the backend reads
`$SLURM_TMPDIR` first), and pass `--backend apptainer --image agent.sif`.

Checks, from the repository root:

| command | what it checks |
| --- | --- |
| `.venv/bin/pytest -q tests/launch` | parser, inotify, join, tree, tarball, backend argv, and 15 docker launches |
| `.venv/bin/python scripts/mutate-launch-joins.py` | 12 mutants of the join, origin and coverage rules; each must fail the tests |
| `.venv/bin/python scripts/check-launch-verify.py ./xcheck` | the four runs of the worked example, checked with probity-verify (install it with the done-receipt adapters first) |

The image must provide `strace` 6.6 or later (for `fchmodat2`), `setpriv` and
`/bin/sh`. The launcher checks all three before it runs the agent.

## Run directory

| file | content |
| --- | --- |
| `start.tar` | the workspace before the run, sorted, owner and time fixed; `snapshot.reset` restores it after checking its digest |
| `launch.json` | `probity-launch/v1`: backend, image and image id, runtime and tracer versions, the full container argv, `trace_expression`, `tracer_flags`, `tracer_uid_separated`, agent argv, uid, environment, network, start tarball digest, observer source digest |
| `transcript.txt` | the agent's stdout and stderr |
| `trace.txt` | the raw tracer output |
| `observation.json` | `probity-observation/v3`: `probity-observation/v2` plus `workspace_root` and the exec fields below |
| `capability.json` | `probity-capabilities/v1`: the event types the sensors can see |
| `tree.json` | `probity-tree/v2`: every non-directory entry of the final tree, below |
| `receipt.json` | `probity-launch-receipt/v1`, below |

The three verify records follow `docs/done-receipt.md` in probity-verify and
say `vantage: independent`, `witness_scope: PEER`. The receipt says
`witnessScope: PEER`.

### Receipt fields

`launch_sha256` (SHA-256 of `launch.json`), `trace_expression`, `watch_list`
(each watched directory and when its watch was added), `start_tarball_sha256`,
`tree_sha256` (the digest of the final tree, the same value as in `tree.json`),
`coverage`, `container_exit`, `agent_exit`, `timed_out`, `transcript_sha256`,
`trace_sha256`, the SHA-256 of each record's bytes as `observation_record_sha256`,
`capability_record_sha256` and `tree_record_sha256`, `doesNotAssert`, and
`sensors`:

- `s1_inotify`: change count, `overflow`, `watch_failures`, the watch mask;
- `s2_strace`: `tracer` (`complete` or `lost`), call count, `unparsed_lines`,
  `unresolved` calls, `escapes` (`io_uring_setup`, `ptrace`,
  `process_vm_writev`), and the origin rule;
- `s3_tree`: the tree digest and the counts of files, symbolic links and
  special files;
- `join.unattributed`: changes inotify saw that the trace did not.

Mutations outside the workspace and connect addresses are in the observation
itself, not the receipt, so a reader of the observation alone can recompute a
verdict that depends on them.

## Tree record

`probity-tree/v2` lists every entry that is not a directory: `files` (path to
SHA-256), `executable` (the files with any execute bit, sorted), `symlinks`
(path to the raw link target; never followed) and `special` (path to `fifo`,
`socket`, `char` or `block`). `tree_sha256` is SHA-256 over one line per entry,
sorted by the UTF-8 bytes of the path: `<sha256>  <path>` for a regular file
(what `sha256sum` prints), `x:<sha256>  <path>` for an executable one,
`l:<sha256 of the target bytes>  <path>` for a symbolic link and
`s:<kind>  <path>` for a special file. A link added, removed or retargeted
anywhere in the workspace changes the digest, so a grader that copies the
workspace receives exactly the bound tree.

`scripts/check-launch-verify.py` re-expresses the tree record as
`probity-tree/v1` for the probity-verify commit it pins, which reads only
regular files.

## Events

The trace expression is
`trace=execve,execveat,open,openat,openat2,creat,mkdir,mkdirat,mknod,mknodat,symlink,symlinkat,rename,renameat,renameat2,link,linkat,unlink,unlinkat,rmdir,truncate,ftruncate,chmod,fchmod,fchmodat,fchmodat2,chown,fchown,lchown,fchownat,utime,utimes,utimensat,futimesat,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,mmap,connect,fork,vfork,clone,clone3,chdir,fchdir,io_uring_setup,ptrace,process_vm_writev`,
with `-f -q -y -v -ttt -xx -z`. Only successful calls are recorded. `-v` prints
each exec's environment in full.

| event | from |
| --- | --- |
| `exec` with `argv`, `exe`, `cwd`, `env`, and `exit` when the process ended | `execve`, `execveat`; `exe` is the path the kernel executed, resolved against the process's working directory or the `execveat` descriptor (never `argv[0]`); `cwd` is the process's working directory; `env` holds the members of the environment that change which code runs (`PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSAFEPATH`, `PYTHONSTARTUP`, `PYTHONUSERBASE`, `PYTHONNOUSERSITE`, `PYTHONPYCACHEPREFIX`, `PYTHONWARNINGS`, `PYTEST_ADDOPTS`, `PYTEST_PLUGINS`, `NODE_OPTIONS`, `NODE_PATH`), only those present; the exit status (128 plus the signal number for a signal) goes to the last exec of the process |
| `write` | an open with `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` or `O_APPEND`, `creat`, and a shared writable `mmap` |
| `create`, `rename`, `link`, `unlink`, `truncate` | the matching calls; `rename` and `link` carry `target` |
| `chmod` | mode, owner, timestamp and extended-attribute changes |
| `read` | a read-only open inside the workspace |
| `connect` | `connect`, with no path and with `address`, the socket address as the tracer printed it |

Every mutation outside the workspace is an entry of the observation's
`external_mutations`: `id`, `step` (from the same sequence as `events`, so a
reader can order it against each exec), `time`, `type` (the mutation type),
`paths` (absolute container paths of the sides outside the workspace),
`origin` when a command caused it, and `location`. `location` is `grader_path`
for a Python startup hook (`sitecustomize.py`, `usercustomize.py`, any `.pth`
file), a reward file (`reward.json`, `reward.txt`), or anything under a
`site-packages`, `dist-packages` or `verifier` directory, and
`outside_workspace` otherwise. Paths under `/dev`, `/proc` and `/sys` are left
out.

`exe` and `cwd` are container paths. The observation's `workspace_root` names
the container path of the workspace, so a reader can tell a runner on the
image (`/usr/local/bin/pytest`) from one the agent placed in the workspace
(`/workspace/.bin/pytest`) whose argv is the same.

A rename or link from outside the workspace into it is recorded as a `create`
of the target; a rename from inside to outside, as an `unlink`; a hard link
from an inside file to an outside name, as a `link` on the inside path with no
`target`. No mutation that touches the workspace is left out.

### Origin

A command is a process the agent's root process started, or a process an
interactive shell (one run without `-c`) started. An event's `origin` is the
first exec of the command whose process tree produced it. Events of the agent's
own root process carry none. So `bash -c "edit; pytest"` is one command and its
edit is not counted as an edit after the test run, as `tool_claim_match/v1`
documents; a persistent tool shell's commands are each their own.

## Coverage

| condition | coverage |
| --- | --- |
| inotify queue overflow, or a watch that could not be added | `unknown` |
| tracer lost (no exit record for the root process) | `incomplete`, gap to the end |
| `io_uring_setup`, `ptrace` or `process_vm_writev` | `incomplete`, gap to the end |
| a change inotify saw with no matching traced call | `incomplete`, one-second gap; the change is recorded with no `origin` |
| a call whose directory descriptor printed without a path | `incomplete`, one-second gap |
| a trace line the parser does not recognise | `incomplete`, whole run |
| none of these | `complete` |

## Limits

- Scope is `PEER`. The launcher's host holds every sensor.
- Docker: the tracer runs as root in the container with `CAP_SYS_PTRACE`,
  `CAP_DAC_READ_SEARCH`, `CAP_SETUID` and `CAP_SETGID`, and drops the agent to
  the workspace owner's uid (65534 when the workspace is owned by root). The
  agent cannot signal the tracer or open its descriptors.
- Apptainer: tracer and agent share a uid (`tracer_uid_separated: false`).
  A killed tracer is reported as lost events; a forged trace line is not
  detected.
- bubblewrap is not used: it fails to set up a user namespace on hosts with
  `kernel.apparmor_restrict_unprivileged_userns=1`, including the default
  Ubuntu 24.04 desktop. The older `boundary-probe` command still uses it and
  runs on CI runners.
- Paths from calls other than `open` are normalised but their symbolic links
  are not resolved. inotify reports the real path, so a write through a link
  shows up as an unattributed change.
- Writes through an already-open descriptor (`write`, `pwrite`, `sendfile`)
  are covered by the open that created the descriptor, not traced one by one.
  A descriptor received from outside the container is not seen.
- Reads outside the workspace are not recorded.
