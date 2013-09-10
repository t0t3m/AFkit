# AFkit

### Description

**It is able to:**
  1.  Hide himself from /proc/modules, /proc/kallsyms and /sys/modules
  2.  Hide files with "__rt" substring in their name (and their content)
  3.  Avoid the opening and reading of /dev/mem, /dev/port and /dev/kmem devices

This anti-forensic rootkit uses the system call hijacking method, in particular are hijacked the following syscalls:
  * open
  * read
  * getdents
  * getdents64
  * chdir
  * kill

### ToDo

  1. Hide network communications
  2. Hide network ports
  3. Hide process by given PID

## PLEASE REPORT BUGS. IT'LL BE VERY APPRECIATED!

**Tested on ArchLinux Kernel 3.10.10 but it is supposed to work on all 3.x versions.**  
**Beta quality product. I don't take any responsability about it's usage and it's behaviour**
