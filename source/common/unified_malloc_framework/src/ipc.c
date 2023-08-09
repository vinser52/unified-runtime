/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "umf/ipc.h"

#include "memory_pool_internal.h"
#include "memory_tracker.h"

#include <assert.h>
#include <stdlib.h>

struct umf_ipc_data_t {
    // TODO: uint32_t or uint16_t should be enough because IPC handle is small.
    uint64_t size;
    uint64_t offset;
    char providerData[];
};

enum umf_result_t
umfGetIPCHandle(const void *ptr, umf_ipc_handle_t *umfIPCHandle, size_t *size) {
    size_t ipcHandleSize = 0;
    struct umf_alloc_info_t allocInfo;
    enum umf_result_t res =
        umfMemoryTrackerGetAllocInfo(umfMemoryTrackerGet(), ptr, &allocInfo);
    if (res != UMF_RESULT_SUCCESS) {
        return res;
    }

    // TODO: we have no cases with multiple memory providers
    assert(allocInfo.pool->numProviders == 1);
    umf_memory_provider_handle_t provider = allocInfo.pool->providers[0];

    size_t providerIPCHandleSize;
    res = umfMemoryProviderGetIPCHandleSize(provider, &providerIPCHandleSize);
    if (res != UMF_RESULT_SUCCESS) {
        return res;
    }

    ipcHandleSize = sizeof(struct umf_ipc_data_t) + providerIPCHandleSize;
    struct umf_ipc_data_t *ipcData = malloc(ipcHandleSize);
    if (!ipcData) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    res =
        umfMemoryProviderGetIPCHandle(provider, allocInfo.base, allocInfo.size,
                                      (void *)ipcData->providerData);
    if (res != UMF_RESULT_SUCCESS) {
        free(ipcData);
        return res;
    }

    ipcData->size = ipcHandleSize;
    ipcData->offset = (uintptr_t)ptr - (uintptr_t)allocInfo.base;

    *umfIPCHandle = ipcData;
    *size = ipcHandleSize;

    return UMF_RESULT_SUCCESS;
}

enum umf_result_t umfPutIPCHandle(umf_ipc_handle_t umfIPCHandle) {
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

enum umf_result_t umfOpenIPCHandle(umf_memory_pool_handle_t hPool,
                                   umf_ipc_handle_t umfIPCHandle, void **ptr) {
    umf_memory_provider_handle_t hProvider;
    size_t numProviders;
    void *base = NULL;

    // TODO: So far we have no pools that support more then 1 memory providers.
    enum umf_result_t res =
        umfPoolGetMemoryProviders(hPool, 1, &hProvider, &numProviders);
    if (res != UMF_RESULT_SUCCESS) {
        return res;
    }

    umfMemoryProviderOpenIPCHandle(hProvider,
                                   (void *)umfIPCHandle->providerData, &base);

    *ptr = (void *)((uintptr_t)base + umfIPCHandle->offset);

    return UMF_RESULT_SUCCESS;
}

enum umf_result_t umfCloseIPCHandle(void *ptr) {
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
    umf_memory_provider_handle_t hProvider = NULL; // TODO: find memory provider

    return umfMemoryProviderCloseIPCHandle(hProvider, ptr);
}
