# 🧠 RAM Injection Tool in C

A Linux-based memory scanner and editor built in C using the `ptrace` API. This tool attaches to a running process, scans its writable memory regions for a specific integer value, allows rescanning, and even edits memory at runtime.

> ⚠️ This project is strictly for educational and ethical testing purposes only. Unauthorized use on systems you do not own or have permission to test is **illegal**.

---

## 🚀 Features

- Attach to a running process by PID
- Scan memory regions (`/proc/[pid]/maps`) for a specific integer value
- Rescan previously found addresses for updated values
- Modify memory values at known addresses
- Detach safely after operations

---

## 🖥️ How It Works

1. User enters the **PID** of a target process.
2. Tool attaches using `ptrace(PTRACE_ATTACH)`.
3. Parses `/proc/[pid]/maps` to find writable (`rw-p`) regions.
4. Scans these regions using `PTRACE_PEEKDATA` for the target value.
5. Allows rescanning to refine the address list.
6. Uses `PTRACE_POKEDATA` to inject a new integer into memory.

---

## 🛠️ Requirements

- Linux system with `procfs`
- `gcc` or any C compiler
- Root privileges (recommended for full process access)

---

## 🧪 Compilation

```bash
gcc -o ram-injector ram_injector.c
