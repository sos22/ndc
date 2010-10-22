#ifndef NDC_H__
#define NDC_H__

struct process;
struct breakpoint;
struct thread;
struct loaded_object;
struct watchpoint;

struct thread {
	struct thread *next, *prev;
	struct process *process;
	pid_t pid;

	int _stop_status; /* from wait() or -1 if it's currently
			   * running */
};

struct loaded_object {
	struct loaded_object *next;
	struct loaded_object *prev;
	struct breakpoint *head_bp;
	char *name;
	bool live;

	unsigned nr_breakpoints;

	unsigned nr_instrs_alloced;
	unsigned nr_instrs;
	unsigned long *instrs;
};

struct breakpoint {
	struct breakpoint *next;
	struct breakpoint *prev;

	struct breakpoint *next_lo;
	struct breakpoint *prev_lo;

	struct loaded_object *lo;

	unsigned long addr;
	unsigned char old_content;
	void (*f)(struct thread *, struct breakpoint *, void *ctxt,
		  struct user_regs_struct *urs);
	void *ctxt;
};

/* Arggh... When a child clone()s itself, we need to process the
   ptrace event from the parent *before* the SIGSTOP in the child, but
   they sometimes get reordered.  Use a staging buffer. */
struct pending_wait_status {
	unsigned nr_pending;
	unsigned nr_allocated;
	struct {
		int status;
		pid_t pid;
	} *pending;
};

struct process {
	struct thread *head_thread;
	int from_child_fd;
	int to_child_fd;
	unsigned long linker_brk_addr;
	int nr_threads;
	int tgid;

	pid_t timeout_pid;
	bool timeout_fired;

	struct breakpoint *head_breakpoint;
	struct loaded_object *head_loaded_object;

	struct pending_wait_status pws;
};

struct breakpoint *set_breakpoint(struct thread *thr,
				  unsigned long addr,
				  struct loaded_object *lo,
				  void (*f)(struct thread *, struct breakpoint *, void *ctxt,
					    struct user_regs_struct *urs),
				  void *ctxt);
void unset_breakpoint(struct thread *thr, struct breakpoint *bp);

void get_regs(struct thread *thr, struct user_regs_struct *urs);
void set_regs(struct thread *thr, const struct user_regs_struct *urs);
int _fetch_bytes(struct thread *thr, unsigned long addr, void *buf, size_t buf_size);
void store_byte(struct thread *thr, unsigned long addr, unsigned char byte);

struct watchpoint *set_watchpoint(struct process *p, unsigned long addr, unsigned size, int watch_reads);
void unset_watchpoint(struct watchpoint *w);

void resume_child(struct thread *thr);
bool pause_child(struct thread *thr);
void unpause_child(struct thread *thr);

bool receive_ptrace_event(struct process *proc);
void handle_breakpoint(struct thread *thr);

int tgkill(int tgid, int tid, int sig);

int thr_stop_status(const struct thread *thr);
bool thr_is_stopped(const struct thread *thr);
void thr_stopped(struct thread *thr, int status);
void thr_resume(struct thread *thr);

/* Annoyingly, the glibc headers don't include this, and it's hard to
   get the kernel ones to play nicely with the glibc ones.  Use the
   glibc ones and suplement with this one #define from the kernel
   headers. */
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif


#endif /* !NDC_H__ */
