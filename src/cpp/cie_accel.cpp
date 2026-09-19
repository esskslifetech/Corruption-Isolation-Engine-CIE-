/**
 * @file cie_accel.cpp
 * @brief C ABI shim: the C++ performance core of the Python engine.
 *
 * The audit found that `src/cpp/file_analyzer.cpp` was never called by the
 * Python application (0 call sites): the "dual-language architecture" in the
 * README was decorative, and every scan hashed and histogrammed its bytes in
 * Python at roughly 20 MB/s while the C++ side did the same work at 100+ MB/s.
 *
 * This shim closes that gap without forking the implementation:
 *
 *  - `#define CIE_ACCEL_LIBRARY` excludes the standalone tool's `main()` and
 *    the file is included directly, so the SHA-256 and the byte statistics
 *    used here are *literally the same code* the analyzer binary runs.
 *  - A small, allocation-free C ABI is exported for `ctypes`
 *    (src/python/cpp_accel.py).
 *  - Python keeps control of I/O, error mapping and cancellation: it reads the
 *    file in chunks, checks its cancel event between chunks, and calls
 *    cie_accel_ctx_update() for the per-byte work.
 *
 * Symbols are compiled with hidden visibility except the exported entry
 * points, so loading this library into the Python process cannot clash with
 * anything else.
 *
 * Build:  make cpp      (produces build/libcie_accel.so alongside
 *                        build/file_analyzer)
 * Test:   cie_accel_selftest() - returns 0 when the library agrees with known
 *         SHA-256 / entropy values.
 */

#define CIE_ACCEL_LIBRARY 1
#include "file_analyzer.cpp"

#include <cstring>
#include <new>

#if defined(_WIN32)
#define CIE_ACCEL_EXPORT extern "C" __declspec(dllexport)
#else
#define CIE_ACCEL_EXPORT extern "C" __attribute__((visibility("default")))
#endif

/// Bump when the struct layout or the semantics of a function change.
#define CIE_ACCEL_API_VERSION 1

/// One-pass statistics for a file (or any byte stream).
struct cie_accel_stats {
    unsigned long long size_bytes;
    unsigned long long null_bytes;
    unsigned long long printable_bytes;
    unsigned long long unique_bytes;
    unsigned long long max_run_length;
    double shannon_entropy;
    char sha256_hex[65];  ///< lowercase hex, NUL-terminated
};

namespace {

struct AccelContext {
    crypto::Sha256 hasher;
    metrics::ByteStatistics stats;
};

inline std::span<const std::uint8_t> as_bytes(const unsigned char* data, std::size_t length) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(data), length};
}

} // namespace

CIE_ACCEL_EXPORT int cie_accel_api_version(void) {
    return CIE_ACCEL_API_VERSION;
}

/// Create a context. Returns NULL only if the allocation fails.
CIE_ACCEL_EXPORT void* cie_accel_ctx_create(void) {
    return new (std::nothrow) AccelContext();
}

/// Feed one chunk. Returns 0 on success, -1 for a NULL context, -2 for a NULL
/// buffer with a non-zero length.
CIE_ACCEL_EXPORT int cie_accel_ctx_update(void* context, const unsigned char* data, std::size_t length) {
    if (context == nullptr) {
        return -1;
    }
    if (data == nullptr && length != 0U) {
        return -2;
    }

    auto* ctx = static_cast<AccelContext*>(context);
    const auto bytes = as_bytes(data, length);
    ctx->hasher.update(bytes);
    metrics::update(ctx->stats, bytes);
    return 0;
}

/// Finalize into `out`. Returns 0 on success, -1 for NULL arguments.
CIE_ACCEL_EXPORT int cie_accel_ctx_finish(void* context, struct cie_accel_stats* out) {
    if (context == nullptr || out == nullptr) {
        return -1;
    }

    auto* ctx = static_cast<AccelContext*>(context);
    const std::string hex = ctx->hasher.finish_hex();
    if (hex.size() != sizeof(out->sha256_hex) - 1U) {
        return -3;
    }
    std::memcpy(out->sha256_hex, hex.data(), hex.size());
    out->sha256_hex[hex.size()] = '\0';

    out->size_bytes = ctx->stats.total_bytes;
    out->null_bytes = ctx->stats.null_bytes;
    out->printable_bytes = ctx->stats.printable_bytes;
    out->unique_bytes = static_cast<unsigned long long>(metrics::unique_byte_count(ctx->stats));
    out->max_run_length = static_cast<unsigned long long>(ctx->stats.max_run_length);
    out->shannon_entropy = metrics::entropy_bits_per_byte(ctx->stats);
    return 0;
}

/// Release a context. NULL is ignored.
CIE_ACCEL_EXPORT void cie_accel_ctx_free(void* context) {
    delete static_cast<AccelContext*>(context);
}

/**
 * Self-test: hashes known values through the public API and checks the entropy
 * of a constant stream and of a full 0..255 histogram.
 * Returns 0 when every check passes, non-zero otherwise (the failing check's
 * index, so a test failure is diagnosable from Python).
 */
CIE_ACCEL_EXPORT int cie_accel_selftest(void) {
    struct Case {
        const char* data;
        std::size_t length;
        const char* sha256;
        double entropy;
    };

    // SHA-256 test vectors (FIPS 180-4 / NIST examples).
    static const Case cases[] = {
        {"", 0U, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0.0},
        {"abc", 3U, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 1.5849625007211563},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56U,
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 3.994680368408909},
    };

    int index = 0;
    for (const auto& test_case : cases) {
        ++index;
        void* ctx = cie_accel_ctx_create();
        if (ctx == nullptr) {
            return 100 + index;
        }
        struct cie_accel_stats stats{};
        if (cie_accel_ctx_update(ctx, reinterpret_cast<const unsigned char*>(test_case.data), test_case.length) != 0 ||
            cie_accel_ctx_finish(ctx, &stats) != 0) {
            cie_accel_ctx_free(ctx);
            return 200 + index;
        }
        cie_accel_ctx_free(ctx);

        if (stats.size_bytes != test_case.length) {
            return 300 + index;
        }
        if (std::strcmp(stats.sha256_hex, test_case.sha256) != 0) {
            return 400 + index;
        }
        if (std::fabs(stats.shannon_entropy - test_case.entropy) > 1e-9) {
            return 500 + index;
        }
    }

    // All 256 byte values, once: entropy must be exactly 8 bits/byte.
    ++index;
    {
        std::array<unsigned char, 256> all_values{};
        for (std::size_t i = 0; i < all_values.size(); ++i) {
            all_values[i] = static_cast<unsigned char>(i);
        }
        void* ctx = cie_accel_ctx_create();
        struct cie_accel_stats stats{};
        if (ctx == nullptr || cie_accel_ctx_update(ctx, all_values.data(), all_values.size()) != 0 ||
            cie_accel_ctx_finish(ctx, &stats) != 0) {
            cie_accel_ctx_free(ctx);
            return 600 + index;
        }
        cie_accel_ctx_free(ctx);
        if (stats.unique_bytes != 256U || std::fabs(stats.shannon_entropy - 8.0) > 1e-12) {
            return 700 + index;
        }
    }

    return 0;
}
