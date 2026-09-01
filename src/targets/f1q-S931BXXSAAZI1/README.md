# f1q-S931BXXSAAZI1

| Field | Value |
|---|---|
| Device | Samsung Galaxy S25 (SM-S931B, codename `f1q`) |
| Firmware | S931BXXSAAZI1 |
| Android | 17 (API level 37) |
| Kernel | 6.6.127 (Exynos 2500) |
| Region | EUR\_OPEN |

## Status

- **Build**: compiles cleanly against the shared payload sources.
- **Offsets**: **provisional** — copied from S24 Ultra (e3q-S928BXXS6DZF2)
  and must be replaced with values from the SM-S931B OSS kernel drop
  before the exploit will function correctly at runtime.  All offsets
  that require verification are annotated with `/* TODO */` in `target.h`.
- **Fingerprint table**: zero-filled placeholder.  The oracle will report
  "no hit" on every attempt until real fingerprint words are filled in.
  See the comment block at the top of `p0_fingerprint.h` for the
  extraction procedure.

## Updating offsets

```sh
# Extract from the OSS kernel source or a live vmlinux:
nm -n out/vmlinux | grep -E \
  'ashmem_fops|anon_pipe_buf_ops|init_task|root_task_group|\
selinux_enforcing|kmalloc_caches|call_usermodehelper_exec_work|\
system_unbound_wq|nfulnl_instance_table|random_table|sysctl_bootid'
```

Subtract `KIMAGE_TEXT_BASE` (`0xffffffc008000000`) from each address to
obtain the `_OFF` constant, then update `target.h`.
