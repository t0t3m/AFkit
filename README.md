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

** UPDATE 19/04/2014**
**Tested on ArchLinux with Kernel 3.14.1 (x86_64) and Debian Wheezy with kernel 3.12 (686)**  

### ToDo

  1. Hide network connections
  2. Hide network ports
  3. Hide process by given PID

## PLEASE REPORT BUGS. IT'LL BE VERY APPRECIATED!

**Tested on ArchLinux Kernel 3.10.10 (x86_64) but it is supposed to work on all 3.x versions.**  
**Beta quality product. I don't take any responsability about its usage and its behaviour.**
