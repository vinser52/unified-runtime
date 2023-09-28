/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
 * See LICENSE.TXT
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "memory_tracker.h"
#include "critnib/critnib.h"
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

#include <cassert>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

struct tracker_value_t {
    size_t size;
    void *pool;
};
// TODO: reimplement in C and optimize...
struct umf_memory_tracker_t {
    enum umf_result_t add(void *pool, const void *ptr, size_t size) {
        std::unique_lock<std::shared_mutex> lock(mtx);

        if (size == 0) {
            return UMF_RESULT_SUCCESS;
        }

        auto ret = map.try_emplace(reinterpret_cast<uintptr_t>(ptr),
                                   tracker_value_t{size, pool});
        return ret.second ? UMF_RESULT_SUCCESS : UMF_RESULT_ERROR_UNKNOWN;
    }

    enum umf_result_t remove(const void *ptr, size_t size) {
        std::unique_lock<std::shared_mutex> lock(mtx);

        map.erase(reinterpret_cast<uintptr_t>(ptr));

        // TODO: handle removing part of the range
        (void)size;

        return UMF_RESULT_SUCCESS;
    }

    bool find(const void *ptr, umf_alloc_info_t *pAllocInfo) {
        std::shared_lock<std::shared_mutex> lock(mtx);

        auto intptr = reinterpret_cast<uintptr_t>(ptr);
        auto it = map.upper_bound(intptr);
        if (it == map.begin()) {
            return false;
        }

        --it;

        auto address = it->first;
        auto size = it->second.size;
        auto pool = it->second.pool;

        if (intptr >= address && intptr < address + size) {
            pAllocInfo->base = reinterpret_cast<void *>(address);
            pAllocInfo->size = size;
            pAllocInfo->pool = (umf_memory_pool_handle_t)pool;
            return true;
        }

        return false;
    }

  private:
    std::shared_mutex mtx;
    std::map<uintptr_t, tracker_value_t> map;
};

static enum umf_result_t
umfMemoryTrackerAdd(umf_memory_tracker_handle_t hTracker, void *pool,
                    const void *ptr, size_t size) {
    return hTracker->add(pool, ptr, size);
}

static enum umf_result_t
umfMemoryTrackerRemove(umf_memory_tracker_handle_t hTracker, const void *ptr,
                       size_t size) {
    return hTracker->remove(ptr, size);
}

extern "C" {

#if defined(_WIN32) && defined(UMF_SHARED_LIBRARY)
umf_memory_tracker_t *tracker = nullptr;
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_DETACH) {
        delete tracker;
    } else if (fdwReason == DLL_PROCESS_ATTACH) {
        tracker = new umf_memory_tracker_t;
    }
    return TRUE;
}
#elif defined(_WIN32)
umf_memory_tracker_t trackerInstance;
umf_memory_tracker_t *tracker = &trackerInstance;
#else
umf_memory_tracker_t *tracker = nullptr;
void __attribute__((constructor)) createLibTracker() {
    tracker = new umf_memory_tracker_t;
}

void __attribute__((destructor)) deleteLibTracker() { delete tracker; }
#endif

umf_memory_tracker_handle_t umfMemoryTrackerGet(void) { return tracker; }

void *umfMemoryTrackerGetPool(umf_memory_tracker_handle_t hTracker,
                              const void *ptr) {
    struct umf_alloc_info_t allocInfo;
    return hTracker->find(ptr, &allocInfo) ? allocInfo.pool : nullptr;
}

enum umf_result_t
umfMemoryTrackerGetAllocInfo(umf_memory_tracker_handle_t hTracker,
                             const void *ptr, umf_alloc_info_t *pAllocInfo) {
    return hTracker->find(ptr, pAllocInfo) ? UMF_RESULT_SUCCESS
                                           : UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

struct ipc_cache_value_t {
    uint64_t size;
    char ipcData[];
};

struct umf_tracking_memory_provider_t {
    umf_memory_provider_handle_t hUpstream;
    umf_memory_tracker_handle_t hTracker;
    umf_memory_pool_handle_t pool;
    critnib *ipcCache;
};

typedef struct umf_tracking_memory_provider_t umf_tracking_memory_provider_t;

static enum umf_result_t trackingAlloc(void *hProvider, size_t size,
                                       size_t alignment, void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;
    enum umf_result_t ret = UMF_RESULT_SUCCESS;

    if (!p->hUpstream) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    ret = umfMemoryProviderAlloc(p->hUpstream, size, alignment, ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    ret = umfMemoryTrackerAdd(p->hTracker, p->pool, *ptr, size);
    if (ret != UMF_RESULT_SUCCESS && p->hUpstream) {
        if (umfMemoryProviderFree(p->hUpstream, *ptr, size)) {
            // TODO: LOG
        }
    }

    return ret;
}

static enum umf_result_t trackingFree(void *hProvider, void *ptr, size_t size) {
    enum umf_result_t ret;
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hProvider;

    // umfMemoryTrackerRemove should be called before umfMemoryProviderFree
    // to avoid a race condition. If the order would be different, other thread
    // could allocate the memory at address `ptr` before a call to umfMemoryTrackerRemove
    // resulting in inconsistent state.
    ret = umfMemoryTrackerRemove(p->hTracker, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        return ret;
    }

    void *value = critnib_remove(p->ipcCache, (uintptr_t)ptr);
    if (value) {
        struct ipc_cache_value_t *cache_value =
            (struct ipc_cache_value_t *)value;
        ret = umfMemoryProviderPutIPCHandle(p->hUpstream, cache_value->ipcData);
        assert(ret == UMF_RESULT_SUCCESS);
        free(value);
    }

    ret = umfMemoryProviderFree(p->hUpstream, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        if (umfMemoryTrackerAdd(p->hTracker, p->pool, ptr, size) !=
            UMF_RESULT_SUCCESS) {
            // TODO: LOG
        }
        return ret;
    }

    return ret;
}

static enum umf_result_t trackingInitialize(void *params, void **ret) {
    umf_tracking_memory_provider_t *provider =
        (umf_tracking_memory_provider_t *)malloc(
            sizeof(umf_tracking_memory_provider_t));
    if (!provider) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    *provider = *((umf_tracking_memory_provider_t *)params);
    *ret = provider;
    return UMF_RESULT_SUCCESS;
}

static void trackingFinalize(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    critnib_delete(p->ipcCache);
    free(provider);
}

static void trackingGetLastError(void *provider, const char **msg,
                                 int32_t *pError) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    umfMemoryProviderGetLastNativeError(p->hUpstream, msg, pError);
}

static enum umf_result_t
trackingGetRecommendedPageSize(void *provider, size_t size, size_t *pageSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetRecommendedPageSize(p->hUpstream, size,
                                                   pageSize);
}

static enum umf_result_t trackingGetMinPageSize(void *provider, void *ptr,
                                                size_t *pageSize) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetMinPageSize(p->hUpstream, ptr, pageSize);
}

static enum umf_result_t trackingPurgeLazy(void *provider, void *ptr,
                                           size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderPurgeLazy(p->hUpstream, ptr, size);
}

static enum umf_result_t trackingPurgeForce(void *provider, void *ptr,
                                            size_t size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderPurgeForce(p->hUpstream, ptr, size);
}

static const char *trackingName(void *provider) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetName(p->hUpstream);
}

static enum umf_result_t trackingGetIpcHandleSize(void *provider,
                                                  size_t *size) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderGetIPCHandleSize(p->hUpstream, size);
}

static enum umf_result_t trackingGetIpcHandle(void *provider, const void *ptr,
                                              size_t size, void *ipcData) {
    enum umf_result_t ret = UMF_RESULT_SUCCESS;
    size_t ipcDataSize = 0;
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;

    void *value = critnib_get(p->ipcCache, (uintptr_t)ptr);
    if (value) { //cache hit
        struct ipc_cache_value_t *cache_value =
            (struct ipc_cache_value_t *)value;
        memcpy(ipcData, cache_value->ipcData, cache_value->size);
    } else { // cache miss
        enum umf_result_t ret =
            umfMemoryProviderGetIPCHandle(p->hUpstream, ptr, size, ipcData);
        if (ret != UMF_RESULT_SUCCESS) {
            return ret;
        }

        ret = umfMemoryProviderGetIPCHandleSize(p->hUpstream, &ipcDataSize);
        assert(ret == UMF_RESULT_SUCCESS);

        size_t value_size = sizeof(struct ipc_cache_value_t) + ipcDataSize;
        struct ipc_cache_value_t *cache_value =
            (struct ipc_cache_value_t *)malloc(value_size);

        cache_value->size = ipcDataSize;
        memcpy(cache_value->ipcData, ipcData, ipcDataSize);

        int inserted = critnib_insert(p->ipcCache, (uintptr_t)ptr,
                                      (void *)cache_value, 0 /*update*/);
        assert(inserted != 0);
    }
    return ret;
}

static enum umf_result_t trackingPutIpcHandle(void *provider, void *ipcData) {
    // We just keep ipcData in the provider->ipcCache.
    // The actual Put is called inside trackingFree
    return UMF_RESULT_SUCCESS;
}

static enum umf_result_t trackingOpenIpcHandle(void *provider, void *ipcData,
                                               void **ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderOpenIPCHandle(p->hUpstream, ipcData, ptr);
}

static enum umf_result_t trackingCloseIpcHandle(void *provider, void *ptr) {
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)provider;
    return umfMemoryProviderCloseIPCHandle(p->hUpstream, ptr);
}

enum umf_result_t umfTrackingMemoryProviderCreate(
    umf_memory_provider_handle_t hUpstream, umf_memory_pool_handle_t hPool,
    umf_memory_provider_handle_t *hTrackingProvider) {
    umf_tracking_memory_provider_t params;
    params.hUpstream = hUpstream;
    params.hTracker = umfMemoryTrackerGet();
    params.pool = hPool;
    params.ipcCache = critnib_new();

    struct umf_memory_provider_ops_t trackingMemoryProviderOps;
    trackingMemoryProviderOps.version = UMF_VERSION_CURRENT;
    trackingMemoryProviderOps.initialize = trackingInitialize;
    trackingMemoryProviderOps.finalize = trackingFinalize;
    trackingMemoryProviderOps.alloc = trackingAlloc;
    trackingMemoryProviderOps.free = trackingFree;
    trackingMemoryProviderOps.get_last_native_error = trackingGetLastError;
    trackingMemoryProviderOps.get_min_page_size = trackingGetMinPageSize;
    trackingMemoryProviderOps.get_recommended_page_size =
        trackingGetRecommendedPageSize;
    trackingMemoryProviderOps.purge_force = trackingPurgeForce;
    trackingMemoryProviderOps.purge_lazy = trackingPurgeLazy;
    trackingMemoryProviderOps.get_name = trackingName;
    trackingMemoryProviderOps.get_ipc_handle_size = trackingGetIpcHandleSize;
    trackingMemoryProviderOps.get_ipc_handle = trackingGetIpcHandle;
    trackingMemoryProviderOps.put_ipc_handle = trackingPutIpcHandle;
    trackingMemoryProviderOps.open_ipc_handle = trackingOpenIpcHandle;
    trackingMemoryProviderOps.close_ipc_handle = trackingCloseIpcHandle;

    return umfMemoryProviderCreate(&trackingMemoryProviderOps, &params,
                                   hTrackingProvider);
}

void umfTrackingMemoryProviderGetUpstreamProvider(
    umf_memory_provider_handle_t hTrackingProvider,
    umf_memory_provider_handle_t *hUpstream) {
    assert(hUpstream);
    umf_tracking_memory_provider_t *p =
        (umf_tracking_memory_provider_t *)hTrackingProvider;
    *hUpstream = p->hUpstream;
}
}
