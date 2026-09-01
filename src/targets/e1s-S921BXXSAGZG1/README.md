# e1s-S921BXXSAGZG1

| Field            | Value                                                             |
|------------------|-------------------------------------------------------------------|
| **Codename**     | e1s (Galaxy S25)                                                  |
| **Model**        | SM-S921B                                                          |
| **Firmware**     | S921BXXSAGZG1                                                     |
| **Android**      | 17 (API 37)                                                       |
| **Kernel**       | 6.6.127-android16-11                                              |
| **KMI**          | android16-6.6                                                     |
| **SoC**          | Exynos 2500                                                       |
| **Arch**         | AArch64                                                           |
| **CVE**          | CVE-2026-43499                                                    |
| **Build type**   | user / release-keys                                               |

## Notes

Offsets derived from the `android16-6.6` kernel image shipped with One UI 8
(Android 17). The `KIMAGE_TEXT_BASE`, page-offset, and physmap boundaries are
unchanged from the 6.1 S25 targets; only the symbol offsets were re-extracted
from the new vmlinux. `P0_FINGERPRINT_*` constants carry forward the same
32-slide / 5-word-minimum tuning used on all other e1s targets.
