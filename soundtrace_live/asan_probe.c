/*
 * SoundTrace CyberGym ASan capture shim (Linux x86-64 only).
 *
 * Preloaded into the pinned vulnerable benchmark image via LD_PRELOAD.
 * Registers an ASan error-report callback through the weak sanitizer
 * interface and, when a report fires, writes exactly ONE bounded JSONL
 * event line to the runner-private mount /soundtrace/events.jsonl.
 *
 * Constraints (reviewed, fixed code):
 *   - built with: clang -shared -fPIC -nostdlib -fno-stack-protector
 *   - NO libc calls and NO allocation in the callback path; raw
 *     openat/write/close syscalls via inline assembly only;
 *   - fixed-size stack buffers, manual integer formatting;
 *   - the callback is registered only when EVERY weak symbol resolved;
 *   - a once-flag guarantees at most one event line per process;
 *   - only whitelisted region categories ("heap") are emitted;
 *   - the human ASan stderr report is never parsed.
 */
typedef unsigned long uptr;

/* Weak ASan runtime interface (all must resolve or we stay inert).
 * Signatures exactly per compiler-rt asan_interface_internal.h:
 *   - get_report_access_type() returns int is_write (0 = read, 1 = write)
 *   - locate_address(addr, name, name_size, &region_address, &region_size)
 *     returns the region category string ("heap", "stack", "global", ...) */
extern void __asan_set_error_report_callback(void (*cb)(const char *))
    __attribute__((weak));
extern uptr __asan_get_report_address(void) __attribute__((weak));
extern int __asan_get_report_access_type(void) __attribute__((weak));
extern uptr __asan_get_report_access_size(void) __attribute__((weak));
extern const char *__asan_get_report_description(void) __attribute__((weak));
extern uptr __asan_get_report_pc(void) __attribute__((weak));
extern const char *__asan_locate_address(uptr addr, char *name, uptr name_size,
                                         uptr *region_address,
                                         uptr *region_size)
    __attribute__((weak));

#define SYS_write  1
#define SYS_close  3
#define SYS_openat 257
#define AT_FDCWD   (-100)
/* O_WRONLY | O_CREAT | O_APPEND */
#define ST_O_FLAGS 02101 /* 1 | 64 | 1024 */
#define ST_O_MODE  0600

static long sys_call3(long n, long a, long b, long c) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(n), "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return ret;
}

static long sys_call4(long n, long a, long b, long c, long d) {
  long ret;
  register long r10 __asm__("r10") = d;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                   : "rcx", "r11", "memory");
  return ret;
}

static void raw_append(int fd, const char *buf, uptr n) {
  uptr off = 0;
  while (off < n) {
    long w = sys_call3(SYS_write, (long)fd, (long)(buf + off),
                       (long)(n - off));
    if (w <= 0)
      return; /* best effort; runner treats a missing event as inconclusive */
    off += (uptr)w;
  }
}

#define ST_LINE_MAX 2048
#define ST_DESC_MAX 64

static int st_streq(const char *s, const char *t) {
  uptr i = 0;
  while (s[i] != 0 && s[i] == t[i])
    i++;
  return s[i] == t[i];
}

static char *st_fmt_u64(char *p, uptr v) {
  char tmp[20];
  int n = 0;
  do {
    tmp[n++] = (char)('0' + (v % 10));
    v /= 10;
  } while (v != 0);
  while (n > 0)
    *p++ = tmp[--n];
  return p;
}

static const char st_hexdigits[] = "0123456789abcdef";

/* Append a JSON-escaped, length-bounded string (quotes/backslashes and
 * control characters escaped; UTF-8 bytes >= 0x20 pass through). */
static char *st_json_str(char *p, const char *s, uptr cap) {
  *p++ = '"';
  for (uptr i = 0; i < cap && s[i] != 0; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"' || c == '\\') {
      *p++ = '\\';
      *p++ = (char)c;
    } else if (c < 0x20) {
      *p++ = '\\';
      *p++ = 'u';
      *p++ = '0';
      *p++ = '0';
      *p++ = st_hexdigits[(c >> 4) & 0xf];
      *p++ = st_hexdigits[c & 0xf];
    } else {
      *p++ = (char)c;
    }
  }
  *p++ = '"';
  return p;
}

static volatile int st_done = 0;

static void st_on_report(const char *report) {
  (void)report; /* human prose is deliberately ignored */
  if (st_done)
    return;
  st_done = 1;

  if (!__asan_get_report_address || !__asan_get_report_access_type ||
      !__asan_get_report_access_size || !__asan_get_report_description ||
      !__asan_get_report_pc || !__asan_locate_address)
    return; /* unsupported ASan ABI: no event, runner says inconclusive */

  uptr address = __asan_get_report_address();
  int is_write = __asan_get_report_access_type();
  uptr width = __asan_get_report_access_size();
  uptr pc = __asan_get_report_pc();
  const char *description = __asan_get_report_description();

  const char *access_kind = is_write ? "write" : "read";

  char region_name[128];
  uptr region_base = 0;
  uptr region_size = 0;
  const char *region_category = __asan_locate_address(
      address, region_name, sizeof(region_name), &region_base, &region_size);
  /* Whitelisted region categories only. */
  if (!region_category || !st_streq(region_category, "heap"))
    return;
  if (description == 0)
    description = "";

  char line[ST_LINE_MAX];
  char *p = line;
  const char *lit =
      "{\"index\":1,\"kind\":\"asan_report\",\"event_id\":\"A1\",\"address\":";
  while (*lit)
    *p++ = *lit++;
  p = st_fmt_u64(p, address);
  *p++ = ',';
  *p++ = '"'; *p++ = 'a'; *p++ = 'c'; *p++ = 'c'; *p++ = 'e'; *p++ = 's';
  *p++ = 's'; *p++ = '_'; *p++ = 'k'; *p++ = 'i'; *p++ = 'n'; *p++ = 'd';
  *p++ = '"'; *p++ = ':';
  p = st_json_str(p, access_kind, 8);
  *p++ = ',';
  *p++ = '"'; *p++ = 'w'; *p++ = 'i'; *p++ = 'd'; *p++ = 't'; *p++ = 'h';
  *p++ = '"'; *p++ = ':';
  p = st_fmt_u64(p, width);
  *p++ = ',';
  *p++ = '"'; *p++ = 'd'; *p++ = 'e'; *p++ = 's'; *p++ = 'c'; *p++ = 'r';
  *p++ = 'i'; *p++ = 'p'; *p++ = 't'; *p++ = 'i'; *p++ = 'o'; *p++ = 'n';
  *p++ = '"'; *p++ = ':';
  p = st_json_str(p, description, ST_DESC_MAX);
  *p++ = ',';
  *p++ = '"'; *p++ = 'p'; *p++ = 'c'; *p++ = '"'; *p++ = ':';
  p = st_fmt_u64(p, pc);
  *p++ = ',';
  *p++ = '"'; *p++ = 'r'; *p++ = 'e'; *p++ = 'g'; *p++ = 'i'; *p++ = 'o';
  *p++ = 'n'; *p++ = '_'; *p++ = 'c'; *p++ = 'a'; *p++ = 't'; *p++ = 'e';
  *p++ = 'g'; *p++ = 'o'; *p++ = 'r'; *p++ = 'y'; *p++ = '"'; *p++ = ':';
  p = st_json_str(p, "heap", 4);
  *p++ = ',';
  *p++ = '"'; *p++ = 'r'; *p++ = 'e'; *p++ = 'g'; *p++ = 'i'; *p++ = 'o';
  *p++ = 'n'; *p++ = '_'; *p++ = 'b'; *p++ = 'a'; *p++ = 's'; *p++ = 'e';
  *p++ = '"'; *p++ = ':';
  p = st_fmt_u64(p, region_base);
  *p++ = ',';
  *p++ = '"'; *p++ = 'r'; *p++ = 'e'; *p++ = 'g'; *p++ = 'i'; *p++ = 'o';
  *p++ = 'n'; *p++ = '_'; *p++ = 'e'; *p++ = 'x'; *p++ = 't'; *p++ = 'e';
  *p++ = 'n'; *p++ = 't'; *p++ = '"'; *p++ = ':';
  p = st_fmt_u64(p, region_size);
  *p++ = ',';
  *p++ = '"'; *p++ = 'p'; *p++ = 'o'; *p++ = 'i'; *p++ = 'n'; *p++ = 't';
  *p++ = 'e'; *p++ = 'r'; *p++ = '_'; *p++ = 'b'; *p++ = 'i'; *p++ = 't';
  *p++ = 's'; *p++ = '"'; *p++ = ':';
  p = st_fmt_u64(p, 64);
  *p++ = '}';
  *p++ = '\n';

  long fd = sys_call4(SYS_openat, (long)AT_FDCWD,
                      (long) "/soundtrace/events.jsonl",
                      (long)ST_O_FLAGS, (long)ST_O_MODE);
  if (fd < 0)
    return;
  raw_append((int)fd, line, (uptr)(p - line));
  sys_call3(SYS_close, fd, 0, 0);
}

__attribute__((constructor)) static void st_init(void) {
  /* Register only when the full weak interface is present. */
  if (!__asan_set_error_report_callback || !__asan_get_report_address ||
      !__asan_get_report_access_type || !__asan_get_report_access_size ||
      !__asan_get_report_description || !__asan_get_report_pc ||
      !__asan_locate_address)
    return;
  __asan_set_error_report_callback(st_on_report);
}
