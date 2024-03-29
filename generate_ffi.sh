#!/bin/sh
bindgen unicorn/include/unicorn/unicorn.h \
    -o src/ffi.rs \
    --use-core \
    --size_t-is-usize \
    --no-layout-tests  \
    --no-prepend-enum-name \
    --allowlist-type '^uc_.+' \
    --allowlist-function '^uc_.+' \
    --no-copy '^uc_engine' \
    --no-copy '^uc_context' \
    -- \
    -include inttypes.h \
    -include stdbool.h \
    -include stddef.h \
    -DUNICORN_ARM_H \
    -DUNICORN_ARM64_H \
    -DUNICORN_M68K_H \
    -DUNICORN_MIPS_H \
    -DUNICORN_PPC_H \
    -DUNICORN_RISCV_H \
    -DUNICORN_SPARC_H \
    -DUNICORN_PLATFORM_H \
    -Duc_struct=uc_engine
