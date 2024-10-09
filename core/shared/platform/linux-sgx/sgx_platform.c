/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"
#if defined(WAMR_FAASM) && defined(FAASM_SGX_HARDWARE_MODE)
#include "sgx_mm.h"
#else
#include "sgx_rsrv_mem_mngr.h"
#endif

// Faasm: additional import to workaround a discrepancy with function
// signatures
#ifdef WAMR_FAASM
#include <enclave/inside/ocalls_wamr.h>
#endif

#if WASM_ENABLE_SGX_IPFS != 0
#include "sgx_ipfs.h"
#endif

static os_print_function_t print_function = NULL;

int
bh_platform_init()
{
    int ret = BHT_OK;

#if WASM_ENABLE_SGX_IPFS != 0
    ret = ipfs_init();
#endif

    return ret;
}

void
bh_platform_destroy()
{
#if WASM_ENABLE_SGX_IPFS != 0
    ipfs_destroy();
#endif
}

void *
os_malloc(unsigned size)
{
    return malloc(size);
}

void *
os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void
os_free(void *ptr)
{
    free(ptr);
}

int
os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

int
putchar(int c)
{
    return 0;
}

int
puts(const char *s)
{
    return 0;
}

void
os_set_print_function(os_print_function_t pf)
{
    print_function = pf;
}

#define FIXED_BUFFER_SIZE 4096

int
os_printf(const char *message, ...)
{
    int bytes_written = 0;

#ifndef WAMR_FAASM
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        va_list ap;
        va_start(ap, message);
        vsnprintf(msg, FIXED_BUFFER_SIZE, message, ap);
        va_end(ap);
        bytes_written += print_function(msg);
    }
#else
    // Faasm: WAMR has changed the signature for os_print_function_t making it
    // return an integer. The way we define ocalls (through our own header file
    // and not using the Edger8r's generated one) means that there's a
    // signature discrepancy with functions that return one value. The simplest
    // fix is to hack the os_printf and os_vprintf implementations for SGX.
    char msg[FIXED_BUFFER_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, message);
    vsnprintf(msg, FIXED_BUFFER_SIZE, message, ap);
    va_end(ap);
    int actual_written;
    ocallLogWamr(&actual_written, msg);
    bytes_written += actual_written;
#endif

    return bytes_written;
}

int
os_vprintf(const char *format, va_list arg)
{
    int bytes_written = 0;

#ifndef WAMR_FAASM
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        vsnprintf(msg, FIXED_BUFFER_SIZE, format, arg);
        bytes_written += print_function(msg);
    }
#else
    // Faasm: WAMR has changed the signature for os_print_function_t making it
    // return an integer. The way we define ocalls (through our own header file
    // and not using the Edger8r's generated one) means that there's a
    // signature discrepancy with functions that return one value. The simplest
    // fix is to hack the os_printf and os_vprintf implementations for SGX.
    char msg[FIXED_BUFFER_SIZE] = { '\0' };
    vsnprintf(msg, FIXED_BUFFER_SIZE, format, arg);
    int actual_written;
    ocallLogWamr(&actual_written, msg);
    bytes_written += actual_written;
#endif

    return bytes_written;
}

char *
strcpy(char *dest, const char *src)
{
    const unsigned char *s = src;
    unsigned char *d = dest;

    while ((*d++ = *s++)) {
    }
    return dest;
}

#if WASM_ENABLE_LIBC_WASI == 0
bool
os_is_handle_valid(os_file_handle *handle)
{
    assert(handle != NULL);

    return *handle > -1;
}
#else
/* implemented in posix_file.c */
#endif

void *
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    int mprot = 0;
    uint64 aligned_size, page_size;
    void *ret = NULL;

    if (os_is_handle_valid(&file)) {
        os_printf("os_mmap(size=%u, prot=0x%x, file=%x) failed: file is not "
                  "supported.\n",
                  size, prot, file);
        return NULL;
    }

    page_size = getpagesize();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

    if (aligned_size >= UINT32_MAX)
        return NULL;

#if defined(WAMR_FAASM)
    // SGX MM does not support the 32BIT flag
    if (flags == MMAP_MAP_32BIT) {
        os_printf("skipping MMAP\n");
        return NULL;
    }
#endif

#if defined(WAMR_FAASM) && defined(FAASM_SGX_HARDWARE_MODE)
    // In Faasm we want to use the EDMM API for dynamic memory management.
    // The main header is in /opt/intel/sgxsd/include/sgx_mm.h
    // Annoyingly, the symbols seem to be only defined in the HW mode libraries
    // (not in the simulation ones).

    int ret_code = sgx_mm_alloc(NULL, aligned_size, SGX_EMA_COMMIT_NOW, NULL, NULL, &ret);
    if (ret == NULL || ret_code != 0) {
        os_printf("os_mm_mmap(size=%u, aligned size=%lu, prot=0x%x) failed: %i\n",
                  size, aligned_size, prot, ret_code);

        return NULL;
    }

    if (prot & MMAP_PROT_READ)
        mprot |= SGX_EMA_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_EMA_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_EMA_PROT_EXEC;

    ret_code = sgx_mm_modify_permissions(ret, aligned_size, mprot);
    if (ret_code != 0) {
        os_printf("os_mmap(size=%u, prot=0x%x) failed to set protect: %s\n",
                  size, prot, strerror(ret_code));
        sgx_mm_dealloc(ret, aligned_size);
        return NULL;
    }
#else
    sgx_status_t st = 0;

    ret = sgx_alloc_rsrv_mem(aligned_size);
    if (ret == NULL) {
        os_printf("os_mmap(size=%u, aligned size=%lu, prot=0x%x) failed.\n",
                  size, aligned_size, prot);
        return NULL;
    }

    if (prot & MMAP_PROT_READ)
        mprot |= SGX_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_PROT_EXEC;

    st = sgx_tprotect_rsrv_mem(ret, aligned_size, mprot);
    if (st != SGX_SUCCESS) {
        os_printf("os_mmap(size=%u, prot=0x%x) failed to set protect.\n", size,
                  prot);
        sgx_free_rsrv_mem(ret, aligned_size);
        return NULL;
    }
#endif

    return ret;
}

void
os_munmap(void *addr, size_t size)
{
    uint64 aligned_size, page_size;

    page_size = getpagesize();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

#if defined(WAMR_FAASM) && defined(FAASM_SGX_HARDWARE_MODE)
    int ret_code = sgx_mm_dealloc(addr, aligned_size);

    if (ret_code != 0)
        os_printf("os_munmap: error deallocating memory");
#else
    sgx_free_rsrv_mem(addr, aligned_size);
#endif
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    int mprot = 0;
    sgx_status_t st = 0;
    uint64 aligned_size, page_size;

    page_size = getpagesize();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

#if defined(WAMR_FAASM) && defined(FAASM_SGX_HARDWARE_MODE)
    if (prot & MMAP_PROT_READ)
        mprot |= SGX_EMA_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_EMA_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_EMA_PROT_EXEC;

    int ret_code = sgx_mm_modify_permissions(addr, aligned_size, mprot);
    if (ret_code != 0)
#else
    if (prot & MMAP_PROT_READ)
        mprot |= SGX_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_PROT_EXEC;
    st = sgx_tprotect_rsrv_mem(addr, aligned_size, mprot);
    if (st != SGX_SUCCESS)
#endif
        os_printf("os_mprotect(addr=0x%" PRIx64 ", size=%u, prot=0x%x) failed.",
                  (uintptr_t)addr, size, prot);

    return (st == SGX_SUCCESS ? 0 : -1);
}

void
os_dcache_flush(void)
{}

void
os_icache_flush(void *start, size_t len)
{}
