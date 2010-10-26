#ifndef NDC_H__
#define NDC_H__

struct process;
struct breakpoint;
struct thread;
struct loaded_object;
struct watchpoint;

#define offsetof(type, field)			        \
(unsigned long)&((type *)0)->field

#define container_of(strct, type, field)		\
(type *)((unsigned long)strct - offsetof(type, field))

struct list_entry {
	struct list_entry *next, *prev;
};

struct list_head {
	struct list_entry content;
};

static inline void
init_list_entry(struct list_entry *le)
{
	le->next = le->prev = le;
}

static inline void
init_list_head(struct list_head *le)
{
	le->content.next = &le->content;
	le->content.prev = &le->content;
}

static inline bool
list_empty(const struct list_head *lh)
{
	return lh->content.next == &lh->content;
}

static inline void
list_unlink(struct list_entry *le)
{
	le->next->prev = le->prev;
	le->prev->next = le->next;
	le->next = le;
	le->prev = le;
}

static inline struct list_entry *
_list_pop(struct list_head *lh)
{
	struct list_entry *l = lh->content.next;
	assert(!list_empty(lh));
	list_unlink(l);
	return l;
}

static inline void
_list_push(struct list_head *lh, struct list_entry *what)
{
	what->next = &lh->content;
	what->prev = lh->content.prev;
	what->next->prev = what;
	what->prev->next = what;
}

#define list_foreach(lh, cursor, field)		                \
	for (cursor = container_of((lh)->content.next,		\
				   typeof(*cursor),		\
				   field);			\
	     cursor != container_of(&(lh)->content,		\
				    typeof(*cursor),		\
				    field);			\
	     cursor = container_of(cursor->field.next,		\
				   typeof(*cursor),		\
				   field))
#define list_foreach_careful(lh, cursor, field, nxt)		\
	for (cursor = container_of((lh)->content.next,		\
				   typeof(*cursor),		\
				   field),			\
		     nxt = container_of(cursor->field.next,	\
					 typeof(*cursor),	\
					 field);		\
	     cursor != container_of(&(lh)->content,		\
				    typeof(*cursor),		\
				    field);			\
	     cursor = nxt,					\
		     nxt = container_of(cursor->field.next,	\
					typeof(*cursor),	\
					field))

#define list_first(lh, type, field)			        \
	({							\
		assert(!list_empty(lh));			\
		container_of((lh)->content.next, type, field);	\
	})

#define list_pop(typ, field, head)			\
	container_of(_list_pop(head), typ, field)
#define list_push(what, field, head)		        \
	_list_push( (head), &(what)->field)

struct thread {
	struct list_entry list;
	struct process *process;
	pid_t pid;

	int _stop_status; /* from wait() or -1 if it's currently
			   * running */
};

struct loaded_object {
	struct list_entry list;
	struct list_head breakpoints;

	char *name;
	bool live;

	unsigned nr_breakpoints;

	unsigned next_instr_to_set_bp_on;

	unsigned nr_instrs_alloced;
	unsigned nr_instrs;
	unsigned long *instrs;
};

struct breakpoint {
	struct list_entry list_process;
	struct list_entry list_loaded_object;

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
	struct list_head threads;

	int from_child_fd;
	int to_child_fd;
	unsigned long linker_brk_addr;
	int nr_threads;
	int tgid;

	pid_t timeout_pid;
	bool timeout_fired;

	struct list_head breakpoints;
	struct list_head loaded_objects;

	struct pending_wait_status pws;
};

/* An x86 instruction consists of

   -- Some prefixes
   -- One or two bytes of opcode
   -- An optional modrm,sib,disp complex
   -- Some bytes of immediate data

   The template gives you the breakdown of the instruction into those
   bytes, and also tells you the type of modrm which is in use (read,
   write, no-access, etc.)

   Prefixes should really be divided into legacy and REX blocks, where
   there is at most one REX prefix, but we don't bother.
*/
struct instr_template {
	int bytes_prefix;
	int bytes_opcode;
	int bytes_modrm; /* includes SIB and displacement, if present */
	int bytes_immediate;
	int modrm_access_type;
};

/* Invalid -> there is no modrm, none -> there is a modrm but it's not
 * used to access memory */
#define ACCESS_INVALID 0
#define ACCESS_R 1
#define ACCESS_W 2
#define ACCESS_RW 3
#define ACCESS_NONE 4


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

void find_instr_template(const unsigned char *instr,
			 unsigned long addr,
			 struct instr_template *it,
			 unsigned *prefixes);
unsigned long eval_modrm_addr(const unsigned char *modrm_bytes,
			      const struct instr_template *it,
			      unsigned prefixes,
			      const struct user_regs_struct *urs);
struct loaded_object *process_shlib(struct process *p, unsigned long start_vaddr,
				    unsigned long end_vaddr, unsigned long offset,
				    const char *fname);

void add_mem_access_instr(struct loaded_object *lo, unsigned long addr, int mode);


void my_setenv(const char *name, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sanity_check_lo(const struct loaded_object *lo);
void dsleep(double x);

void vmsg(int prio, const char *fmt, va_list args);
void msg(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void dump_debug_ring(void);

#ifdef VERY_LOUD
#define PRIO_RING 0
#define PRIO_STDOUT 0
#define PRIO_STDERR 20
#else
#define PRIO_RING 0
#define PRIO_STDOUT 10
#define PRIO_STDERR 20
#endif

/* Annoyingly, the glibc headers don't include this, and it's hard to
   get the kernel ones to play nicely with the glibc ones.  Use the
   glibc ones and suplement with this one #define from the kernel
   headers. */
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif


#endif /* !NDC_H__ */
