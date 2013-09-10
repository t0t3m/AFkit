AFkit
=====

Description
-----------

Anti-Forensic linux LKM rootkit

**It is able to:**
  - Hide himself from /proc/modules, /proc/kallsyms and /sys/modules
  - Hide files with "__rt" substring in their name (and their content)
  - Avoid the opening and reading of /dev/mem, /dev/port and /dev/kmem devices

This anti-forensic rootkit uses the system call hijacking method, in particular are hijacked the following syscalls:
  - open
  - read
  - getdents
  - getdents64
  - chdir
  - kill

**Tested on ArchLinux Kernel 3.10.10 but it is supposed to work on all 3.x versions.**

