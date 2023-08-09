/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <assert.h>
#include <stdlib.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "umf/memory_provider.h"

#include "memory_provider_internal.h"

struct umf_memory_provider_t {
    struct umf_memory_provider_ops_t ops;
    void *provider_priv;
};

std::vector<struct umf_memory_provider_ops_t> globalProviders;

enum umf_result_t
umfMemoryProviderCreate(const struct umf_memory_provider_ops_t *ops,
                        void *params, umf_memory_provider_handle_t *hProvider) {
    umf_memory_provider_handle_t provider =
        (umf_memory_provider_t *)malloc(sizeof(struct umf_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    assert(ops->version == UMF_VERSION_CURRENT);

    provider->ops = *ops;

    void *provider_priv;
    enum umf_result_t ret = ops->initialize(params, &provider_priv);
    if (ret != UMF_RESULT_SUCCESS) {
        free(provider);
        return ret;
    }

    provider->provider_priv = provider_priv;

    *hProvider = provider;

    return UMF_RESULT_SUCCESS;
}

enum umf_result_t umfMemoryProviderRegister(umf_memory_provider_ops_t *ops) {

    // TODO check if this provider isn't already registered
    globalProviders.push_back(*ops);

    return UMF_RESULT_SUCCESS;
}

enum umf_result_t
umfMemoryProvidersRegistryGet(umf_memory_provider_ops_t *providers,
                              size_t *numProviders) {

    if (providers == NULL) {
        *numProviders = globalProviders.size();
    } else {
        memcpy(providers, globalProviders.data(),
               sizeof(umf_memory_provider_ops_t) * *numProviders);
    }

    return UMF_RESULT_SUCCESS;
}

// TODO rename ;)
const umf_memory_provider_ops_t *umfMemoryProvidersRegistryGetOps(char *name) {
    auto it = std::find_if(
        std::begin(globalProviders), std::end(globalProviders),
        [&](auto &ops) { return std::strcmp(ops.get_name(NULL), name) == 0; });

    if (it != globalProviders.end()) {
        return &(*it);
    }

    // else
    return NULL;
}

void umfMemoryProviderDestroy(umf_memory_provider_handle_t hProvider) {
    hProvider->ops.finalize(hProvider->provider_priv);
    free(hProvider);
}

static void
checkErrorAndSetLastProvider(enum umf_result_t result,
                             umf_memory_provider_handle_t hProvider) {
    if (result != UMF_RESULT_SUCCESS) {
        *umfGetLastFailedMemoryProviderPtr() = hProvider;
    }
}

enum umf_result_t umfMemoryProviderAlloc(umf_memory_provider_handle_t hProvider,
                                         size_t size, size_t alignment,
                                         void **ptr) {
    enum umf_result_t res =
        hProvider->ops.alloc(hProvider->provider_priv, size, alignment, ptr);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

enum umf_result_t umfMemoryProviderFree(umf_memory_provider_handle_t hProvider,
                                        void *ptr, size_t size) {
    enum umf_result_t res =
        hProvider->ops.free(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

void umfMemoryProviderGetLastNativeError(umf_memory_provider_handle_t hProvider,
                                         const char **ppMessage,
                                         int32_t *pError) {
    hProvider->ops.get_last_native_error(hProvider->provider_priv, ppMessage,
                                         pError);
}

void *umfMemoryProviderGetPriv(umf_memory_provider_handle_t hProvider) {
    return hProvider->provider_priv;
}

enum umf_result_t
umfMemoryProviderGetRecommendedPageSize(umf_memory_provider_handle_t hProvider,
                                        size_t size, size_t *pageSize) {
    enum umf_result_t res = hProvider->ops.get_recommended_page_size(
        hProvider->provider_priv, size, pageSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

enum umf_result_t
umfMemoryProviderGetMinPageSize(umf_memory_provider_handle_t hProvider,
                                void *ptr, size_t *pageSize) {
    enum umf_result_t res = hProvider->ops.get_min_page_size(
        hProvider->provider_priv, ptr, pageSize);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

enum umf_result_t
umfMemoryProviderPurgeLazy(umf_memory_provider_handle_t hProvider, void *ptr,
                           size_t size) {
    enum umf_result_t res =
        hProvider->ops.purge_lazy(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

enum umf_result_t
umfMemoryProviderPurgeForce(umf_memory_provider_handle_t hProvider, void *ptr,
                            size_t size) {
    enum umf_result_t res =
        hProvider->ops.purge_force(hProvider->provider_priv, ptr, size);
    checkErrorAndSetLastProvider(res, hProvider);
    return res;
}

const char *umfMemoryProviderGetName(umf_memory_provider_handle_t hProvider) {
    return hProvider->ops.get_name(hProvider->provider_priv);
}

enum umf_result_t
umfMemoryProviderGetIPCHandleSize(umf_memory_provider_handle_t hProvider,
                                  size_t *size) {
    return hProvider->ops.get_ipc_handle_size(hProvider->provider_priv, size);
}

enum umf_result_t
umfMemoryProviderGetIPCHandle(umf_memory_provider_handle_t hProvider,
                              const void *ptr, size_t size, void *ipcData) {
    return hProvider->ops.get_ipc_handle(hProvider->provider_priv, ptr, size,
                                         ipcData);
}

enum umf_result_t
umfMemoryProviderPutIPCHandle(umf_memory_provider_handle_t hProvider,
                              void *ipcData) {
    return hProvider->ops.put_ipc_handle(hProvider->provider_priv, ipcData);
}

enum umf_result_t
umfMemoryProviderOpenIPCHandle(umf_memory_provider_handle_t hProvider,
                               void *ipcData, void **ptr) {
    return hProvider->ops.open_ipc_handle(hProvider->provider_priv, ipcData,
                                          ptr);
}

enum umf_result_t
umfMemoryProviderCloseIPCHandle(umf_memory_provider_handle_t hProvider,
                                void *ptr) {
    return hProvider->ops.close_ipc_handle(hProvider->provider_priv, ptr);
}

umf_memory_provider_handle_t umfGetLastFailedMemoryProvider(void) {
    return *umfGetLastFailedMemoryProviderPtr();
}
