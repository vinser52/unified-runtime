// Copyright (C) 2023 Intel Corporation
// Part of the Unified-Runtime Project, under the Apache License v2.0 with LLVM Exceptions.
// See LICENSE.TXT
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "pool.hpp"

#include <cstring>
#include <functional>
#include <random>

#ifndef UMF_TEST_MEMORY_POOL_OPS_HPP
#define UMF_TEST_MEMORY_POOL_OPS_HPP

struct umfPoolTest : umf_test::test,
                     ::testing::WithParamInterface<
                         std::function<umf::pool_unique_handle_t(void)>> {
    umfPoolTest() : pool(nullptr, nullptr) {}
    void SetUp() override {
        test::SetUp();
        this->pool = makePool();
    }

    void TearDown() override { test::TearDown(); }

    umf::pool_unique_handle_t makePool() {
        auto pool = this->GetParam()();
        EXPECT_NE(pool, nullptr);
        return pool;
    }

    umf::pool_unique_handle_t pool;
};

struct umfMultiPoolTest : umfPoolTest {
    static constexpr auto numPools = 16;

    void SetUp() override {
        umfPoolTest::SetUp();

        pools.emplace_back(std::move(pool));
        for (size_t i = 1; i < numPools; i++) {
            pools.emplace_back(makePool());
        }
    }

    void TearDown() override { umfPoolTest::TearDown(); }

    std::vector<umf::pool_unique_handle_t> pools;
};

TEST_P(umfPoolTest, allocFree) {
    static constexpr size_t allocSize = 64;
    auto *ptr = umfPoolMalloc(pool.get(), allocSize);
    ASSERT_NE(ptr, nullptr);
    std::memset(ptr, 0, allocSize);
    umfPoolFree(pool.get(), ptr);
}

TEST_P(umfPoolTest, pow2AlignedAlloc) {
#ifdef _WIN32
    // TODO: implement support for windows
    GTEST_SKIP();
#endif

    static constexpr size_t maxAlignment = (1u << 22);
    static constexpr size_t numAllocs = 4;

    for (size_t alignment = 1; alignment <= maxAlignment; alignment <<= 1) {
        std::cout << alignment << std::endl;
        std::vector<void *> allocs;

        for (size_t alloc = 0; alloc < numAllocs; alloc++) {
            auto *ptr = umfPoolAlignedMalloc(pool.get(), alignment, alignment);
            ASSERT_NE(ptr, nullptr);
            ASSERT_TRUE(reinterpret_cast<uintptr_t>(ptr) % alignment == 0);
            std::memset(ptr, 0, alignment);
            allocs.push_back(ptr);
        }

        for (auto &ptr : allocs) {
            umfPoolFree(pool.get(), ptr);
        }
    }
}

// TODO: add similar tests for realloc/aligned_alloc, etc.
// TODO: add multithreaded tests
TEST_P(umfMultiPoolTest, memoryTracking) {
    static constexpr int allocSizes[] = {1,  2,  4,  8,   16,   20,
                                         32, 40, 64, 128, 1024, 4096};
    static constexpr auto nAllocs = 256;

    std::mt19937_64 g(0);
    std::uniform_int_distribution allocSizesDist(
        0, static_cast<int>(std::size(allocSizes) - 1));
    std::uniform_int_distribution poolsDist(0,
                                            static_cast<int>(pools.size() - 1));

    std::vector<std::tuple<void *, size_t, umf_memory_pool_handle_t>> ptrs;
    for (size_t i = 0; i < nAllocs; i++) {
        auto &pool = pools[poolsDist(g)];
        auto size = allocSizes[allocSizesDist(g)];

        auto *ptr = umfPoolMalloc(pool.get(), size);
        ASSERT_NE(ptr, nullptr);

        ptrs.emplace_back(ptr, size, pool.get());
    }

    for (auto [ptr, size, expectedPool] : ptrs) {
        auto pool = umfPoolByPtr(ptr);
        ASSERT_EQ(pool, expectedPool);

        pool = umfPoolByPtr(reinterpret_cast<void *>(
            reinterpret_cast<intptr_t>(ptr) + size - 1));
        ASSERT_EQ(pool, expectedPool);
    }

    for (auto p : ptrs) {
        umfFree(std::get<0>(p));
    }
}

#endif /* UMF_TEST_MEMORY_POOL_OPS_HPP */
