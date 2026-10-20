/*
 * SoundTrace controlled out-of-bounds access fixture.
 *
 * Trusted, fixed instrumentation: eight enumerated cases, one heap allocation,
 * one tested scalar access per run. Events are JSONL on the dedicated pipe fd
 * 3; stderr carries only the raw sanitizer diagnostic. The runner never
 * accepts a source path, flags, or environment from the agent.
 *
 * Case table (extent, offset, width, operation, guarded):
 *   read_upper      6   4  4  read   no
 *   write_upper     6   4  4  write  no
 *   read_lower     16  -4  4  read   no
 *   write_lower    16  -4  4  write  no
 *   read_in_bounds 16  12  4  read   no
 *   write_in_bounds 16  12  4  write  no
 *   read_patched    6   4  4  read   yes
 *   write_patched   6   4  4  write  yes
 */
#include <stdarg.h>
#include <sanitizer/asan_interface.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EMIT_FD 3

static volatile uint32_t sink;

typedef struct {
    const char *name;
    size_t extent;
    long long offset;
    size_t width;
    char access_kind[6];
    int guarded;
} Case;

static const Case CASES[] = {
    {"read_upper", 6, 4, 4, "read", 0},
    {"write_upper", 6, 4, 4, "write", 0},
    {"read_lower", 16, -4, 4, "read", 0},
    {"write_lower", 16, -4, 4, "write", 0},
    {"read_in_bounds", 16, 12, 4, "read", 0},
    {"write_in_bounds", 16, 12, 4, "write", 0},
    {"read_patched", 6, 4, 4, "read", 1},
    {"write_patched", 6, 4, 4, "write", 1},
};

static unsigned g_index = 0;

/* Bounded formatting: vsnprintf's return value is the required length, so it
 * is clamped before write(); a formatter can never overread its buffer. */
static void emit(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) {
        _exit(5);
    }
    if ((size_t)n > sizeof buf - 1) {
        n = (int)(sizeof buf - 1);
    }
    if (write(EMIT_FD, buf, (size_t)n) != (size_t)n) {
        _exit(5); /* instrumentation-write failure: capture is inconclusive */
    }
}

static void emit_asan_record(unsigned long long address, const char *kind,
                             size_t width, const char *description,
                             unsigned long long pc) {
    /* Bounded stack buffers only; no allocation on the reporting path. */
    char desc_bounded[32];
    size_t i = 0;
    if (description) {
        for (; i < sizeof desc_bounded - 1 && description[i]; i++) {
            desc_bounded[i] = (description[i] >= 32 && description[i] < 127)
                                  ? description[i] : '?';
        }
    }
    desc_bounded[i] = 0;
    emit("{\"index\":%u,\"kind\":\"asan\",\"event_id\":\"A1\",\"address\":%llu,"
         "\"access_kind\":\"%s\",\"width\":%zu,\"description\":\"%s\","
         "\"pc\":%llu}\n",
         ++g_index, address, kind, width, desc_bounded, pc);
}

static const char *g_access_kind = "read";
static unsigned long long g_attempt_address = 0;
static size_t g_attempt_width = 0;

static void on_report(const char *description) {
    (void)description; /* the callback argument is the full report text */
    if (__asan_report_present() != 1) {
        return;
    }
    const char *kind = __asan_get_report_access_type() == 1 ? "write" : "read";
    emit_asan_record((unsigned long long)(uintptr_t)__asan_get_report_address(),
                     kind, __asan_get_report_access_size(),
                     __asan_get_report_description(),
                     (unsigned long long)(uintptr_t)__asan_get_report_pc());
}

static int checked_target(uintptr_t base, long long offset, uintptr_t *out) {
    if (offset >= 0) {
        uintptr_t delta = (uintptr_t)offset;
        if (delta > UINTPTR_MAX - base) {
            return 0;
        }
        *out = base + delta;
    } else {
        uintptr_t delta = (uintptr_t)(-offset);
        if (delta > base) {
            return 0;
        }
        *out = base - delta;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    const Case *selected = NULL;
    for (size_t i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
        if (strcmp(argv[1], CASES[i].name) == 0) {
            selected = &CASES[i];
            break;
        }
    }
    if (!selected) {
        return 2;
    }

    unsigned char *base = (unsigned char *)malloc(selected->extent);
    if (!base) {
        return 3; /* allocation failure: capture is inconclusive */
    }
    memset(base, 0x41, selected->extent);

    char locator_name[64];
    void *locator_base = NULL;
    size_t locator_extent = 0;
    const char *category = __asan_locate_address(base, locator_name,
                                                 sizeof locator_name,
                                                 &locator_base, &locator_extent);
    if (!category || strcmp(category, "heap") != 0
            || (uintptr_t)locator_base != (uintptr_t)base
            || locator_extent != selected->extent) {
        free(base);
        return 3; /* locator failure: capture is inconclusive */
    }

    unsigned pointer_bits = (unsigned)(sizeof(uintptr_t) * __CHAR_BIT__);
    emit("{\"index\":%u,\"kind\":\"alloc\",\"object_id\":\"O1\",\"generation\":1,"
         "\"base\":%llu,\"extent\":%zu,\"pointer_bits\":%u,"
         "\"locator_category\":\"heap\",\"locator_base\":%llu,"
         "\"locator_extent\":%zu}\n",
         ++g_index, (unsigned long long)(uintptr_t)base, selected->extent,
         pointer_bits, (unsigned long long)(uintptr_t)locator_base,
         locator_extent);

    /* Operation identity A1 is reserved before the patched guard is
     * evaluated; identity alone is not an access witness. */
    if (selected->guarded) {
        /* The patched bounds guard, evaluated in exactly this order; the
         * access happens only when the full predicate holds. */
        int safe = selected->offset >= 0
                && selected->width <= selected->extent
                && (size_t)selected->offset <= selected->extent - selected->width;
        if (!safe) {
            emit("{\"index\":%u,\"kind\":\"blocked\",\"event_id\":\"A1\","
                 "\"object_id\":\"O1\",\"generation\":1,"
                 "\"access_kind\":\"%s\"}\n",
                 ++g_index, selected->access_kind);
            emit("{\"index\":%u,\"kind\":\"free\",\"object_id\":\"O1\","
                 "\"generation\":1}\n", ++g_index);
            free(base);
            return 0;
        }
    }

    uintptr_t address;
    if (!checked_target((uintptr_t)base, selected->offset, &address)) {
        free(base);
        return 4; /* address arithmetic would wrap: never attempt it */
    }

    g_access_kind = selected->access_kind;
    g_attempt_address = (unsigned long long)address;
    g_attempt_width = selected->width;
    emit("{\"index\":%u,\"kind\":\"attempt\",\"event_id\":\"A1\","
         "\"object_id\":\"O1\",\"generation\":1,\"address\":%llu,"
         "\"width\":%zu,\"access_kind\":\"%s\"}\n",
         ++g_index, g_attempt_address, g_attempt_width, g_access_kind);

    __asan_set_error_report_callback(on_report);

    volatile uint32_t *slot = (volatile uint32_t *)address;
    if (selected->access_kind[0] == 'w') {
        *slot = 0x24424247u; /* volatile store: cannot be optimized away */
    } else {
        sink = *slot; /* volatile load: cannot be optimized away */
    }

    __asan_set_error_report_callback(NULL);
    emit("{\"index\":%u,\"kind\":\"complete\",\"event_id\":\"A1\"}\n",
         ++g_index);
    emit("{\"index\":%u,\"kind\":\"free\",\"object_id\":\"O1\","
         "\"generation\":1}\n", ++g_index);
    free(base);
    return 0;
}
