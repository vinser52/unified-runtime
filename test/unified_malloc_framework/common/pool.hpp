/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TEST_POOL_HPP
#define UMF_TEST_POOL_HPP 1

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif
#include <umf/base.h>
#include <umf/memory_provider.h>

#include <gtest/gtest.h>
#include <stdlib.h>

#include "base.hpp"
#include "umf_helpers.hpp"

namespace umf_test {

auto wrapPoolUnique(umf_memory_pool_handle_t hPool) {
    return umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
}

struct pool_base {
    umf_result_t initialize(umf_memory_provider_handle_t *, size_t) noexcept {
        return UMF_RESULT_SUCCESS;
    };
    void *malloc(size_t size) noexcept { return nullptr; }
    void *calloc(size_t, size_t) noexcept { return nullptr; }
    void *realloc(void *, size_t) noexcept { return nullptr; }
    void *aligned_malloc(size_t, size_t) noexcept { return nullptr; }
    size_t malloc_usable_size(void *) noexcept { return 0; }
    enum umf_result_t free(void *) noexcept { return UMF_RESULT_SUCCESS; }
    enum umf_result_t get_last_allocation_error() noexcept {
        return UMF_RESULT_SUCCESS;
    }
};

struct malloc_pool : public pool_base {
    void *malloc(size_t size) noexcept { return ::malloc(size); }
    void *calloc(size_t num, size_t size) noexcept {
        return ::calloc(num, size);
    }
    void *realloc(void *ptr, size_t size) noexcept {
        return ::realloc(ptr, size);
    }
    void *aligned_malloc(size_t size, size_t alignment) noexcept {
#ifdef _WIN32
        // we could use _aligned_malloc but it requires using _aligned_free...
        return nullptr;
#else
        return ::aligned_alloc(alignment, size);
#endif
    }
    size_t malloc_usable_size(void *ptr) noexcept {
#ifdef _WIN32
        return _msize(ptr);
#elif __APPLE__
        return ::malloc_size(ptr);
#else
        return ::malloc_usable_size(ptr);
#endif
    }
    enum umf_result_t free(void *ptr) noexcept {
        ::free(ptr);
        return UMF_RESULT_SUCCESS;
    }
};

struct proxy_pool : public pool_base {
    umf_result_t initialize(umf_memory_provider_handle_t *providers,
                            size_t numProviders) noexcept {
        this->provider = providers[0];
        return UMF_RESULT_SUCCESS;
    }
    void *malloc(size_t size) noexcept { return aligned_malloc(size, 0); }
    void *calloc(size_t num, size_t size) noexcept {
        void *ptr;
        auto ret = umfMemoryProviderAlloc(provider, num * size, 0, &ptr);

        memset(ptr, 0, num * size);

        if (ptr) {
            EXPECT_EQ_NOEXCEPT(ret, UMF_RESULT_SUCCESS);
        }
        return ptr;
    }
    void *realloc(void *ptr, size_t size) noexcept {
        // TODO: not supported
        return nullptr;
    }
    void *aligned_malloc(size_t size, size_t alignment) noexcept {
        void *ptr;
        auto ret = umfMemoryProviderAlloc(provider, size, alignment, &ptr);
        if (ptr) {
            EXPECT_EQ_NOEXCEPT(ret, UMF_RESULT_SUCCESS);
        }
        return ptr;
    }
    size_t malloc_usable_size(void *ptr) noexcept {
        // TODO: not supported
        return 0;
    }
    enum umf_result_t free(void *ptr) noexcept {
        auto ret = umfMemoryProviderFree(provider, ptr, 0);
        EXPECT_EQ_NOEXCEPT(ret, UMF_RESULT_SUCCESS);
        return ret;
    }
    umf_memory_provider_handle_t provider;
};

} // namespace umf_test

#endif /* UMF_TEST_POOL_HPP */
