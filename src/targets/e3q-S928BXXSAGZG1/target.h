#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "e3q-S928BXXSAGZG1-app-physical-p0-oracle"
#define APP_PHYS_P0_ORACLE 1
#else
#define BUILD_VARIANT_LABEL "e3q-S928BXXSAGZG1-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "samsung/e3qxxx/e3q:17/BP4A.260101.001/S928BXXSAGZG1:user/release-keys"
#endif

#include "../e1s-S921BXXSAGZG1/target.h"

#undef  BUILD_VARIANT_LABEL
#undef  BUILD_FINGERPRINT
#undef  P0_FINGERPRINT_HEADER

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "e3q-S928BXXSAGZG1-app-physical-p0-oracle"
#define P0_FINGERPRINT_HEADER \
  "targets/e3q-S928BXXSAGZG1/p0_fingerprint.h"
#else
#define BUILD_VARIANT_LABEL "e3q-S928BXXSAGZG1-root-umh"
#endif

#define BUILD_FINGERPRINT \
  "samsung/e3qxxx/e3q:17/BP4A.260101.001/S928BXXSAGZG1:user/release-keys"

#endif
