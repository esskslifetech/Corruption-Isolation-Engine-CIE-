/*
 * High-performance File Analyzer for CIE
 * C++ module for fast binary file analysis and corruption detection
 * 
 * This Project Is Made By Kanishk Soni
 */

/**
 * @file file_analyzer.cpp
 * @brief Concurrent binary file analyzer with deterministic results, strong error handling,
 *        duplicate detection, JSON output, and built-in tests.
 *
 * Design goals:
 * - Clear separation between pure analysis logic and side effects.
 * - Modern C++20, deterministic behavior, and low shared mutable state.
 * - Full-file streaming metrics with bounded memory use.
 * - Safe concurrency through futures instead of shared result mutation.
 * - Practical heuristics: SHA-256, entropy, null ratio, printable ratio,
 *   repeating pattern detection, magic number validation, duplicate grouping.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <ranges>
#include <source_location>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <variant>
#include <vector>

namespace fs = std::filesystem;

// ============================================================================
// 1. UTILITIES
// ============================================================================
namespace util {

template <typename E>
struct ErrorHolder {
    E value;
};

template <typename T, typename E>
class Result {
public:
    static Result success(T value) {
        return Result(std::move(value));
    }

    static Result failure(E error) {
        return Result(ErrorHolder<E>{std::move(error)});
    }

    [[nodiscard]] bool has_value() const noexcept {
        return std::holds_alternative<T>(storage_);
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return has_value();
    }

    [[nodiscard]] const T& value() const& {
        return std::get<T>(storage_);
    }

    [[nodiscard]] T& value() & {
        return std::get<T>(storage_);
    }

    [[nodiscard]] T&& value() && {
        return std::get<T>(std::move(storage_));
    }

    [[nodiscard]] const E& error() const& {
        return std::get<ErrorHolder<E>>(storage_).value;
    }

    [[nodiscard]] E& error() & {
        return std::get<ErrorHolder<E>>(storage_).value;
    }

    [[nodiscard]] E&& error() && {
        return std::get<ErrorHolder<E>>(std::move(storage_)).value;
    }

private:
    std::variant<T, ErrorHolder<E>> storage_;

    explicit Result(T value)
        : storage_(std::move(value)) {}

    explicit Result(ErrorHolder<E> error)
        : storage_(std::move(error)) {}
};

[[nodiscard]] std::size_t default_thread_count() noexcept {
    const auto count = std::thread::hardware_concurrency();
    return count == 0 ? 1U : static_cast<std::size_t>(count);
}

[[nodiscard]] std::string to_lower_copy(std::string_view text) {
    std::string result(text);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return result;
}

[[nodiscard]] std::string join_strings(const std::vector<std::string>& values, std::string_view delimiter) {
    if (values.empty()) {
        return {};
    }

    std::string result = values.front();
    for (std::size_t i = 1; i < values.size(); ++i) {
        result += delimiter;
        result += values[i];
    }
    return result;
}

template <typename T>
[[nodiscard]] Result<T, std::string> parse_unsigned(std::string_view text, std::string_view option_name) {
    T value{};
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);

    if (ec != std::errc{} || ptr != end) {
        return Result<T, std::string>::failure(
            "invalid value for " + std::string(option_name) + ": " + std::string(text));
    }
    return Result<T, std::string>::success(value);
}

[[nodiscard]] std::string json_escape(std::string_view text) {
    std::ostringstream out;

    for (const unsigned char ch : text) {
        switch (ch) {
            case '\"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    out << "\\u"
                        << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(ch)
                        << std::dec << std::setfill(' ');
                } else {
                    out << static_cast<char>(ch);
                }
        }
    }

    return out.str();
}

[[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";

    std::string result;
    result.reserve(bytes.size() * 2);

    for (const auto byte : bytes) {
        result.push_back(digits[(byte >> 4U) & 0x0FU]);
        result.push_back(digits[byte & 0x0FU]);
    }

    return result;
}

} // namespace util

// ============================================================================
// 2. CRYPTOGRAPHY
// ============================================================================
namespace crypto {

/**
 * @brief Streaming SHA-256 implementation.
 *
 * Contract:
 * - Call update() zero or more times.
 * - Call finish_hex() once or multiple times; repeated calls are idempotent.
 * - Do not call update() after finalization.
 */
class Sha256 {
public:
    Sha256() {
        reset();
    }

    void update(std::span<const std::uint8_t> input) noexcept {
        if (finalized_) {
            return;
        }

        for (const auto byte : input) {
            buffer_[buffer_size_++] = byte;
            if (buffer_size_ == buffer_.size()) {
                transform_block(buffer_);
                total_bits_ += 512U;
                buffer_size_ = 0;
            }
        }
    }

    [[nodiscard]] std::string finish_hex() {
        if (finalized_) {
            return digest_hex_;
        }

        const std::uint64_t final_bit_length = total_bits_ + static_cast<std::uint64_t>(buffer_size_) * 8U;

        buffer_[buffer_size_++] = 0x80U;
        if (buffer_size_ > 56U) {
            while (buffer_size_ < buffer_.size()) {
                buffer_[buffer_size_++] = 0x00U;
            }
            transform_block(buffer_);
            buffer_size_ = 0;
        }

        while (buffer_size_ < 56U) {
            buffer_[buffer_size_++] = 0x00U;
        }

        for (std::size_t i = 0; i < 8U; ++i) {
            buffer_[56U + i] = static_cast<std::uint8_t>((final_bit_length >> (56U - i * 8U)) & 0xFFU);
        }

        transform_block(buffer_);

        std::array<std::uint8_t, 32> digest_bytes{};
        for (std::size_t i = 0; i < state_.size(); ++i) {
            digest_bytes[i * 4U + 0U] = static_cast<std::uint8_t>((state_[i] >> 24U) & 0xFFU);
            digest_bytes[i * 4U + 1U] = static_cast<std::uint8_t>((state_[i] >> 16U) & 0xFFU);
            digest_bytes[i * 4U + 2U] = static_cast<std::uint8_t>((state_[i] >> 8U) & 0xFFU);
            digest_bytes[i * 4U + 3U] = static_cast<std::uint8_t>(state_[i] & 0xFFU);
        }

        digest_hex_ = util::hex_encode(digest_bytes);
        finalized_ = true;
        return digest_hex_;
    }

private:
    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t total_bits_{0};
    std::size_t buffer_size_{0};
    bool finalized_{false};
    std::string digest_hex_;

    inline static constexpr std::array<std::uint32_t, 64> kRounds = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    static constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
        return (x & y) ^ (~x & z);
    }

    static constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static constexpr std::uint32_t big_sigma0(std::uint32_t x) noexcept {
        return std::rotr(x, 2U) ^ std::rotr(x, 13U) ^ std::rotr(x, 22U);
    }

    static constexpr std::uint32_t big_sigma1(std::uint32_t x) noexcept {
        return std::rotr(x, 6U) ^ std::rotr(x, 11U) ^ std::rotr(x, 25U);
    }

    static constexpr std::uint32_t small_sigma0(std::uint32_t x) noexcept {
        return std::rotr(x, 7U) ^ std::rotr(x, 18U) ^ (x >> 3U);
    }

    static constexpr std::uint32_t small_sigma1(std::uint32_t x) noexcept {
        return std::rotr(x, 17U) ^ std::rotr(x, 19U) ^ (x >> 10U);
    }

    void reset() noexcept {
        state_ = {
            0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
            0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
        };
        buffer_.fill(0);
        total_bits_ = 0;
        buffer_size_ = 0;
        finalized_ = false;
        digest_hex_.clear();
    }

    void transform_block(const std::array<std::uint8_t, 64>& block) noexcept {
        std::array<std::uint32_t, 64> words{};

        for (std::size_t i = 0; i < 16U; ++i) {
            const std::size_t j = i * 4U;
            words[i] =
                (static_cast<std::uint32_t>(block[j + 0U]) << 24U) |
                (static_cast<std::uint32_t>(block[j + 1U]) << 16U) |
                (static_cast<std::uint32_t>(block[j + 2U]) << 8U) |
                (static_cast<std::uint32_t>(block[j + 3U]));
        }

        for (std::size_t i = 16U; i < 64U; ++i) {
            words[i] = small_sigma1(words[i - 2U]) + words[i - 7U] + small_sigma0(words[i - 15U]) + words[i - 16U];
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];

        for (std::size_t i = 0; i < 64U; ++i) {
            const std::uint32_t temp1 = h + big_sigma1(e) + choose(e, f, g) + kRounds[i] + words[i];
            const std::uint32_t temp2 = big_sigma0(a) + majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }
};

} // namespace crypto

// ============================================================================
// 3. METRICS
// ============================================================================
namespace metrics {

struct ByteStatistics {
    std::array<std::uint64_t, 256> histogram{};
    std::uint64_t total_bytes{0};
    std::uint64_t null_bytes{0};
    std::uint64_t printable_bytes{0};
    bool has_last_byte{false};
    std::uint8_t last_byte{0};
    std::size_t current_run_length{0};
    std::size_t max_run_length{0};
};

constexpr bool is_printable_byte(std::uint8_t value) noexcept {
    return (value >= 32U && value <= 126U) || value == 9U || value == 10U || value == 13U;
}

void update(ByteStatistics& stats, std::span<const std::uint8_t> bytes) noexcept {
    for (const auto value : bytes) {
        ++stats.histogram[value];
        ++stats.total_bytes;

        if (value == 0U) {
            ++stats.null_bytes;
        }

        if (is_printable_byte(value)) {
            ++stats.printable_bytes;
        }

        if (stats.has_last_byte && value == stats.last_byte) {
            ++stats.current_run_length;
        } else {
            stats.has_last_byte = true;
            stats.last_byte = value;
            stats.current_run_length = 1;
        }

        stats.max_run_length = std::max(stats.max_run_length, stats.current_run_length);
    }
}

[[nodiscard]] double ratio(std::uint64_t numerator, std::uint64_t denominator) noexcept {
    if (denominator == 0U) {
        return 0.0;
    }
    return static_cast<double>(numerator) / static_cast<double>(denominator);
}

[[nodiscard]] double entropy_bits_per_byte(const ByteStatistics& stats) noexcept {
    if (stats.total_bytes == 0U) {
        return 0.0;
    }

    double entropy = 0.0;
    for (const auto count : stats.histogram) {
        if (count == 0U) {
            continue;
        }
        const double p = static_cast<double>(count) / static_cast<double>(stats.total_bytes);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

[[nodiscard]] std::size_t unique_byte_count(const ByteStatistics& stats) noexcept {
    return static_cast<std::size_t>(std::count_if(stats.histogram.begin(), stats.histogram.end(), [](std::uint64_t count) {
        return count > 0U;
    }));
}

[[nodiscard]] bool has_repeating_block_pattern(std::span<const std::uint8_t> sample, std::size_t block_size) noexcept {
    if (block_size == 0U) {
        return false;
    }

    const std::size_t full_blocks = sample.size() / block_size;
    if (full_blocks < 3U) {
        return false;
    }

    const auto first_block = sample.first(block_size);
    for (std::size_t block_index = 1; block_index < full_blocks; ++block_index) {
        const auto block_start = sample.begin() + static_cast<std::ptrdiff_t>(block_index * block_size);
        if (!std::equal(first_block.begin(), first_block.end(), block_start)) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] double zero_ratio(std::span<const std::uint8_t> sample) noexcept {
    if (sample.empty()) {
        return 0.0;
    }

    const auto zero_count = static_cast<std::uint64_t>(
        std::count(sample.begin(), sample.end(), static_cast<std::uint8_t>(0U)));
    return ratio(zero_count, static_cast<std::uint64_t>(sample.size()));
}

} // namespace metrics

// ============================================================================
// 4. CORE TYPES AND CONFIGURATION
// ============================================================================
namespace core {

enum class FileStatus {
    Ok,
    Empty,
    HighNullBytes,
    RepeatingPattern,
    MagicMismatch,
    SuspiciousLowEntropy,
    SuspiciousHighEntropyText,
    IoError
};

enum class ContentKind {
    Unknown,
    TextLike,
    StructuredBinary,
    MostlyZero,
    RepeatedPattern,
    CompressedOrEncrypted
};

struct ByteSignature {
    std::size_t offset{0};
    std::vector<std::uint8_t> bytes;
};

using SignatureMap = std::unordered_map<std::string, std::vector<ByteSignature>>;

struct AnalysisConfig {
    bool calculate_sha256{true};
    bool validate_magic_numbers{true};
    bool detect_duplicates{true};
    std::size_t head_sample_size{16U * 1024U};
    std::size_t tail_sample_size{4U * 1024U};
    std::size_t read_chunk_size{256U * 1024U};
    std::size_t repeating_block_size{16U};
    double null_byte_threshold{0.50};
    double low_entropy_threshold{0.02};
    double high_entropy_threshold{7.80};
    double text_printable_ratio_threshold{0.85};
    SignatureMap extra_signatures;
};

struct AnalysisResult {
    std::uint64_t bytes_processed{0};
    std::string sha256_hex;
    double entropy{0.0};
    double null_ratio{0.0};
    double printable_ratio{0.0};
    double tail_zero_ratio{0.0};
    std::size_t unique_byte_count{0};
    std::size_t max_byte_run{0};
    bool magic_number_matched{true};
    bool repeating_pattern_detected{false};
    ContentKind content_kind{ContentKind::Unknown};
    FileStatus status{FileStatus::Ok};
    std::vector<std::string> findings;
};

struct FileReport {
    fs::path path;
    std::string extension;
    std::uint64_t size_bytes{0};
    std::string sha256_hex;
    double entropy{0.0};
    double null_ratio{0.0};
    double printable_ratio{0.0};
    double tail_zero_ratio{0.0};
    std::size_t unique_byte_count{0};
    std::size_t max_byte_run{0};
    ContentKind content_kind{ContentKind::Unknown};
    FileStatus status{FileStatus::Ok};
    std::vector<std::string> findings;
    std::string summary;
    std::size_t duplicate_group_id{0};
    std::size_t duplicate_group_size{1};
    std::chrono::microseconds processing_time{0};
};

[[nodiscard]] const SignatureMap& builtin_signatures() {
    static const SignatureMap signatures = {
        {".pdf",  {{0U, {0x25U, 0x50U, 0x44U, 0x46U}}}},
        {".png",  {{0U, {0x89U, 0x50U, 0x4EU, 0x47U, 0x0DU, 0x0AU, 0x1AU, 0x0AU}}}},
        {".jpg",  {{0U, {0xFFU, 0xD8U, 0xFFU}}}},
        {".jpeg", {{0U, {0xFFU, 0xD8U, 0xFFU}}}},
        {".gif",  {{0U, {'G', 'I', 'F', '8', '7', 'a'}}, {0U, {'G', 'I', 'F', '8', '9', 'a'}}}},
        {".zip",  {{0U, {0x50U, 0x4BU, 0x03U, 0x04U}}, {0U, {0x50U, 0x4BU, 0x05U, 0x06U}}, {0U, {0x50U, 0x4BU, 0x07U, 0x08U}}}},
        {".docx", {{0U, {0x50U, 0x4BU, 0x03U, 0x04U}}}},
        {".xlsx", {{0U, {0x50U, 0x4BU, 0x03U, 0x04U}}}},
        {".gz",   {{0U, {0x1FU, 0x8BU}}}},
        {".bmp",  {{0U, {'B', 'M'}}}},
        {".exe",  {{0U, {'M', 'Z'}}}},
        {".elf",  {{0U, {0x7FU, 'E', 'L', 'F'}}}},
        {".mp4",  {{4U, {'f', 't', 'y', 'p'}}}}
    };
    return signatures;
}

[[nodiscard]] bool is_text_extension(std::string_view extension) noexcept {
    static constexpr std::array<std::string_view, 11> text_extensions = {
        ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".log", ".md", ".ini", ".toml", ".sql"
    };

    return std::find(text_extensions.begin(), text_extensions.end(), extension) != text_extensions.end();
}

[[nodiscard]] constexpr bool is_flagged_status(FileStatus status) noexcept {
    return status != FileStatus::Ok && status != FileStatus::IoError;
}

} // namespace core

// ============================================================================
// 5. ANALYZER
// ============================================================================
namespace analyzer {

namespace detail {

class TailSampler {
public:
    explicit TailSampler(std::size_t capacity)
        : buffer_(capacity) {}

    void push(std::span<const std::uint8_t> bytes) noexcept {
        if (buffer_.empty()) {
            return;
        }

        for (const auto value : bytes) {
            buffer_[write_index_] = value;
            write_index_ = (write_index_ + 1U) % buffer_.size();
            size_ = std::min(size_ + 1U, buffer_.size());
        }
    }

    [[nodiscard]] std::vector<std::uint8_t> snapshot() const {
        std::vector<std::uint8_t> result;
        result.reserve(size_);

        if (size_ == 0U) {
            return result;
        }

        if (size_ < buffer_.size()) {
            result.insert(result.end(), buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(size_));
            return result;
        }

        result.insert(result.end(), buffer_.begin() + static_cast<std::ptrdiff_t>(write_index_), buffer_.end());
        result.insert(result.end(), buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(write_index_));
        return result;
    }

private:
    std::vector<std::uint8_t> buffer_;
    std::size_t write_index_{0};
    std::size_t size_{0};
};

[[nodiscard]] bool matches_signature(std::span<const std::uint8_t> sample, const core::ByteSignature& signature) noexcept {
    if (sample.size() < signature.offset + signature.bytes.size()) {
        return false;
    }

    return std::equal(
        signature.bytes.begin(),
        signature.bytes.end(),
        sample.begin() + static_cast<std::ptrdiff_t>(signature.offset));
}

[[nodiscard]] bool magic_number_matches(
    std::span<const std::uint8_t> sample,
    std::string_view extension,
    const core::AnalysisConfig& config) {

    if (!config.validate_magic_numbers) {
        return true;
    }

    const std::string ext(extension);
    bool has_known_signature = false;

    const auto matches_from_map = [&](const core::SignatureMap& map) {
        const auto it = map.find(ext);
        if (it == map.end()) {
            return false;
        }

        has_known_signature = true;
        return std::any_of(it->second.begin(), it->second.end(), [&](const core::ByteSignature& signature) {
            return matches_signature(sample, signature);
        });
    };

    if (matches_from_map(core::builtin_signatures())) {
        return true;
    }

    if (matches_from_map(config.extra_signatures)) {
        return true;
    }

    return !has_known_signature;
}

[[nodiscard]] core::ContentKind classify_content_kind(
    std::string_view extension,
    double entropy,
    double null_ratio,
    double printable_ratio,
    bool repeating_pattern_detected,
    const core::AnalysisConfig& config) noexcept {

    if (null_ratio >= 0.80) {
        return core::ContentKind::MostlyZero;
    }

    if (repeating_pattern_detected) {
        return core::ContentKind::RepeatedPattern;
    }

    if (core::is_text_extension(extension) ||
        (printable_ratio >= config.text_printable_ratio_threshold && null_ratio < 0.05 && entropy <= 7.20)) {
        return core::ContentKind::TextLike;
    }

    if (entropy >= 7.50 && printable_ratio < 0.30) {
        return core::ContentKind::CompressedOrEncrypted;
    }

    return core::ContentKind::StructuredBinary;
}

[[nodiscard]] core::FileStatus select_primary_status(
    std::uint64_t bytes_processed,
    bool high_null_bytes,
    bool repeating_pattern,
    bool magic_mismatch,
    bool suspicious_low_entropy,
    bool suspicious_high_entropy_text) noexcept {

    if (bytes_processed == 0U) {
        return core::FileStatus::Empty;
    }
    if (high_null_bytes) {
        return core::FileStatus::HighNullBytes;
    }
    if (repeating_pattern) {
        return core::FileStatus::RepeatingPattern;
    }
    if (magic_mismatch) {
        return core::FileStatus::MagicMismatch;
    }
    if (suspicious_low_entropy) {
        return core::FileStatus::SuspiciousLowEntropy;
    }
    if (suspicious_high_entropy_text) {
        return core::FileStatus::SuspiciousHighEntropyText;
    }
    return core::FileStatus::Ok;
}

} // namespace detail

/**
 * @brief Pure stream analyzer.
 *
 * Contract:
 * - Reads the stream from its current position to EOF.
 * - Does not perform filesystem operations.
 * - Returns a value result on analysis completion and an error result on stream failure
 *   or invalid configuration.
 */
class StreamAnalyzer {
public:
    [[nodiscard]] static util::Result<core::AnalysisResult, std::string> analyze(
        std::istream& stream,
        std::string_view extension,
        const core::AnalysisConfig& config) {

        if (config.read_chunk_size == 0U) {
            return util::Result<core::AnalysisResult, std::string>::failure("read_chunk_size must be greater than zero");
        }
        if (config.head_sample_size == 0U) {
            return util::Result<core::AnalysisResult, std::string>::failure("head_sample_size must be greater than zero");
        }
        if (config.repeating_block_size == 0U) {
            return util::Result<core::AnalysisResult, std::string>::failure("repeating_block_size must be greater than zero");
        }

        crypto::Sha256 sha256;
        metrics::ByteStatistics statistics;
        std::vector<std::uint8_t> buffer(config.read_chunk_size);
        std::vector<std::uint8_t> head_sample;
        head_sample.reserve(config.head_sample_size);
        detail::TailSampler tail_sampler(config.tail_sample_size);

        while (true) {
            stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto read_count = stream.gcount();

            if (read_count > 0) {
                const auto chunk_size = static_cast<std::size_t>(read_count);
                const std::span<const std::uint8_t> chunk(buffer.data(), chunk_size);

                if (config.calculate_sha256) {
                    sha256.update(chunk);
                }

                metrics::update(statistics, chunk);
                tail_sampler.push(chunk);

                if (head_sample.size() < config.head_sample_size) {
                    const auto remaining = config.head_sample_size - head_sample.size();
                    const auto copy_size = std::min(remaining, chunk.size());
                    head_sample.insert(head_sample.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(copy_size));
                }
            }

            if (stream.bad()) {
                return util::Result<core::AnalysisResult, std::string>::failure("stream read failed due to I/O error");
            }

            if (stream.eof()) {
                break;
            }

            if (stream.fail()) {
                return util::Result<core::AnalysisResult, std::string>::failure("stream read failed before reaching EOF");
            }
        }

        core::AnalysisResult result;
        result.bytes_processed = statistics.total_bytes;

        if (config.calculate_sha256) {
            result.sha256_hex = sha256.finish_hex();
        }

        if (result.bytes_processed == 0U) {
            result.status = core::FileStatus::Empty;
            result.findings.emplace_back("file is empty");
            return util::Result<core::AnalysisResult, std::string>::success(std::move(result));
        }

        result.entropy = metrics::entropy_bits_per_byte(statistics);
        result.null_ratio = metrics::ratio(statistics.null_bytes, statistics.total_bytes);
        result.printable_ratio = metrics::ratio(statistics.printable_bytes, statistics.total_bytes);
        result.unique_byte_count = metrics::unique_byte_count(statistics);
        result.max_byte_run = statistics.max_run_length;
        result.repeating_pattern_detected = metrics::has_repeating_block_pattern(head_sample, config.repeating_block_size);
        result.magic_number_matched = detail::magic_number_matches(head_sample, extension, config);

        const auto tail_sample = tail_sampler.snapshot();
        result.tail_zero_ratio = metrics::zero_ratio(tail_sample);

        const bool high_null_bytes = result.null_ratio > config.null_byte_threshold;
        const bool repeating_pattern = result.repeating_pattern_detected;
        const bool magic_mismatch = !result.magic_number_matched;
        const bool suspicious_low_entropy = result.entropy <= config.low_entropy_threshold && result.bytes_processed > 4U;
        const bool suspicious_high_entropy_text =
            core::is_text_extension(extension) &&
            result.entropy >= config.high_entropy_threshold &&
            result.printable_ratio < 0.60;

        if (high_null_bytes) {
            result.findings.emplace_back("null byte ratio exceeds configured threshold");
        }
        if (repeating_pattern) {
            result.findings.emplace_back("repeating block pattern detected in header sample");
        }
        if (magic_mismatch) {
            result.findings.emplace_back("magic number does not match file extension");
        }
        if (suspicious_low_entropy) {
            result.findings.emplace_back("entropy is extremely low for a non-trivial file");
        }
        if (suspicious_high_entropy_text) {
            result.findings.emplace_back("text-like extension contains high-entropy non-printable data");
        }
        if (!tail_sample.empty() && result.tail_zero_ratio > 0.95 && result.bytes_processed > tail_sample.size()) {
            result.findings.emplace_back("tail region is mostly zero-filled");
        }

        result.content_kind = detail::classify_content_kind(
            extension,
            result.entropy,
            result.null_ratio,
            result.printable_ratio,
            result.repeating_pattern_detected,
            config);

        result.status = detail::select_primary_status(
            result.bytes_processed,
            high_null_bytes,
            repeating_pattern,
            magic_mismatch,
            suspicious_low_entropy,
            suspicious_high_entropy_text);

        return util::Result<core::AnalysisResult, std::string>::success(std::move(result));
    }
};

} // namespace analyzer

// ============================================================================
// 6. CONCURRENCY AND FILESYSTEM I/O
// ============================================================================
namespace io {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t thread_count)
        : stopping_(false),
          active_tasks_(0) {
        const std::size_t actual_count = std::max<std::size_t>(1U, thread_count);
        workers_.reserve(actual_count);

        for (std::size_t i = 0; i < actual_count; ++i) {
            workers_.emplace_back([this] {
                worker_loop();
            });
        }
    }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    ~ThreadPool() {
        shutdown();
    }

    template <typename F>
    auto submit(F&& function) -> std::future<std::invoke_result_t<F>> {
        using ReturnType = std::invoke_result_t<F>;

        auto task = std::make_shared<std::packaged_task<ReturnType()>>(std::forward<F>(function));
        auto future = task->get_future();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                throw std::runtime_error("submit called on a stopped ThreadPool");
            }

            tasks_.emplace_back([task] {
                (*task)();
            });
        }

        task_ready_.notify_one();
        return future;
    }

    void wait_idle() {
        std::unique_lock<std::mutex> lock(mutex_);
        idle_.wait(lock, [this] {
            return tasks_.empty() && active_tasks_ == 0U;
        });
    }

private:
    using Task = std::function<void()>;

    std::vector<std::jthread> workers_;
    std::deque<Task> tasks_;
    std::mutex mutex_;
    std::condition_variable task_ready_;
    std::condition_variable idle_;
    bool stopping_;
    std::size_t active_tasks_;

    void worker_loop() {
        while (true) {
            Task task;

            {
                std::unique_lock<std::mutex> lock(mutex_);
                task_ready_.wait(lock, [this] {
                    return stopping_ || !tasks_.empty();
                });

                if (stopping_ && tasks_.empty()) {
                    return;
                }

                task = std::move(tasks_.front());
                tasks_.pop_front();
                ++active_tasks_;
            }

            try {
                task();
            } catch (...) {
                // Prevent worker termination. Exceptions are preserved by packaged_task futures.
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                --active_tasks_;
                if (tasks_.empty() && active_tasks_ == 0U) {
                    idle_.notify_all();
                }
            }
        }
    }

    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        task_ready_.notify_all();
        workers_.clear();
    }
};

struct PendingFile {
    fs::path path;
    std::uint64_t size_hint{0};
};

[[nodiscard]] util::Result<std::vector<PendingFile>, std::string> collect_files(
    const fs::path& directory,
    bool recursive) {

    std::error_code ec;
    if (!fs::exists(directory, ec) || ec) {
        return util::Result<std::vector<PendingFile>, std::string>::failure(
            "directory does not exist or cannot be accessed: " + directory.string());
    }
    if (!fs::is_directory(directory, ec) || ec) {
        return util::Result<std::vector<PendingFile>, std::string>::failure(
            "path is not a directory: " + directory.string());
    }

    std::vector<PendingFile> files;
    const auto options = fs::directory_options::skip_permission_denied;

    if (recursive) {
        std::error_code iterator_ec;
        fs::recursive_directory_iterator it(directory, options, iterator_ec);
        const fs::recursive_directory_iterator end;

        for (; it != end; it.increment(iterator_ec)) {
            if (iterator_ec) {
                iterator_ec.clear();
                continue;
            }

            std::error_code status_ec;
            if (!it->is_regular_file(status_ec) || status_ec) {
                continue;
            }

            std::error_code size_ec;
            const auto size = static_cast<std::uint64_t>(it->file_size(size_ec));
            files.push_back(PendingFile{it->path(), size_ec ? 0U : size});
        }
    } else {
        std::error_code iterator_ec;
        fs::directory_iterator it(directory, options, iterator_ec);
        const fs::directory_iterator end;

        for (; it != end; it.increment(iterator_ec)) {
            if (iterator_ec) {
                iterator_ec.clear();
                continue;
            }

            std::error_code status_ec;
            if (!it->is_regular_file(status_ec) || status_ec) {
                continue;
            }

            std::error_code size_ec;
            const auto size = static_cast<std::uint64_t>(it->file_size(size_ec));
            files.push_back(PendingFile{it->path(), size_ec ? 0U : size});
        }
    }

    std::ranges::sort(files, [](const PendingFile& left, const PendingFile& right) {
        return left.path.generic_string() < right.path.generic_string();
    });

    return util::Result<std::vector<PendingFile>, std::string>::success(std::move(files));
}

class ConcurrentFileAnalyzer {
public:
    ConcurrentFileAnalyzer(core::AnalysisConfig config, std::size_t thread_count)
        : config_(std::move(config)),
          thread_count_(std::max<std::size_t>(1U, thread_count)) {}

    [[nodiscard]] util::Result<std::vector<core::FileReport>, std::string> analyze_directory(
        const fs::path& directory,
        bool recursive) const {

        auto files_result = collect_files(directory, recursive);
        if (!files_result) {
            return util::Result<std::vector<core::FileReport>, std::string>::failure(files_result.error());
        }

        auto files = std::move(files_result).value();
        ThreadPool pool(thread_count_);
        std::vector<std::future<core::FileReport>> futures;
        futures.reserve(files.size());

        try {
            for (const auto& file : files) {
                futures.push_back(pool.submit([this, file] {
                    return analyze_one_file(file);
                }));
            }
        } catch (const std::exception& ex) {
            return util::Result<std::vector<core::FileReport>, std::string>::failure(
                std::string("failed to schedule analysis tasks: ") + ex.what());
        }

        std::vector<core::FileReport> reports;
        reports.reserve(files.size());

        for (auto& future : futures) {
            reports.push_back(future.get());
        }

        pool.wait_idle();
        annotate_duplicates(reports);

        return util::Result<std::vector<core::FileReport>, std::string>::success(std::move(reports));
    }

private:
    core::AnalysisConfig config_;
    std::size_t thread_count_;

    [[nodiscard]] core::FileReport analyze_one_file(const PendingFile& file) const {
        const auto start = std::chrono::steady_clock::now();

        core::FileReport report;
        report.path = file.path;
        report.extension = util::to_lower_copy(file.path.extension().string());
        report.size_bytes = file.size_hint;

        try {
            std::ifstream input(file.path, std::ios::binary);
            if (!input) {
                report.status = core::FileStatus::IoError;
                report.findings.emplace_back("failed to open file for reading");
                refresh_summary(report, start);
                return report;
            }

            auto analysis_result = analyzer::StreamAnalyzer::analyze(input, report.extension, config_);
            if (!analysis_result) {
                report.status = core::FileStatus::IoError;
                report.findings.emplace_back(analysis_result.error());
                refresh_summary(report, start);
                return report;
            }

            const auto analysis = std::move(analysis_result).value();
            report.size_bytes = analysis.bytes_processed;
            report.sha256_hex = analysis.sha256_hex;
            report.entropy = analysis.entropy;
            report.null_ratio = analysis.null_ratio;
            report.printable_ratio = analysis.printable_ratio;
            report.tail_zero_ratio = analysis.tail_zero_ratio;
            report.unique_byte_count = analysis.unique_byte_count;
            report.max_byte_run = analysis.max_byte_run;
            report.content_kind = analysis.content_kind;
            report.status = analysis.status;
            report.findings = analysis.findings;

            refresh_summary(report, start);
            return report;
        } catch (const std::exception& ex) {
            report.status = core::FileStatus::IoError;
            report.findings.emplace_back(std::string("unexpected analysis failure: ") + ex.what());
            refresh_summary(report, start);
            return report;
        } catch (...) {
            report.status = core::FileStatus::IoError;
            report.findings.emplace_back("unexpected non-standard analysis failure");
            refresh_summary(report, start);
            return report;
        }
    }

    void refresh_summary(core::FileReport& report, std::chrono::steady_clock::time_point start) const {
        if (report.findings.empty()) {
            report.summary = "no issues detected";
        } else {
            report.summary = util::join_strings(report.findings, "; ");
        }

        const auto end = std::chrono::steady_clock::now();
        report.processing_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    }

    void annotate_duplicates(std::vector<core::FileReport>& reports) const {
        if (!config_.detect_duplicates || !config_.calculate_sha256) {
            return;
        }

        std::unordered_map<std::string, std::vector<std::size_t>> groups;
        groups.reserve(reports.size());

        for (std::size_t i = 0; i < reports.size(); ++i) {
            const auto& report = reports[i];
            if (report.sha256_hex.empty() || report.size_bytes == 0U) {
                continue;
            }

            const std::string key = report.sha256_hex + ":" + std::to_string(report.size_bytes);
            groups[key].push_back(i);
        }

        std::size_t next_group_id = 1U;
        for (std::size_t i = 0; i < reports.size(); ++i) {
            auto& report = reports[i];
            if (!report.sha256_hex.empty() && report.size_bytes > 0U) {
                const std::string key = report.sha256_hex + ":" + std::to_string(report.size_bytes);
                const auto it = groups.find(key);
                if (it != groups.end() && it->second.size() > 1U && report.duplicate_group_id == 0U) {
                    const auto group_size = it->second.size();
                    const auto group_id = next_group_id++;

                    for (const auto index : it->second) {
                        reports[index].duplicate_group_id = group_id;
                        reports[index].duplicate_group_size = group_size;
                        reports[index].findings.emplace_back(
                            "duplicate content group #" + std::to_string(group_id) +
                            " (" + std::to_string(group_size) + " files)");
                        reports[index].summary = util::join_strings(reports[index].findings, "; ");
                    }
                }
            }
        }
    }
};

} // namespace io

// ============================================================================
// 7. REPORTING
// ============================================================================
namespace reporting {

[[nodiscard]] std::string_view status_to_string(core::FileStatus status) noexcept {
    switch (status) {
        case core::FileStatus::Ok: return "OK";
        case core::FileStatus::Empty: return "EMPTY";
        case core::FileStatus::HighNullBytes: return "HIGH_NULL_BYTES";
        case core::FileStatus::RepeatingPattern: return "REPEATING_PATTERN";
        case core::FileStatus::MagicMismatch: return "MAGIC_MISMATCH";
        case core::FileStatus::SuspiciousLowEntropy: return "SUSPICIOUS_LOW_ENTROPY";
        case core::FileStatus::SuspiciousHighEntropyText: return "SUSPICIOUS_HIGH_ENTROPY_TEXT";
        case core::FileStatus::IoError: return "IO_ERROR";
    }
    return "UNKNOWN";
}

[[nodiscard]] std::string_view content_kind_to_string(core::ContentKind kind) noexcept {
    switch (kind) {
        case core::ContentKind::Unknown: return "Unknown";
        case core::ContentKind::TextLike: return "TextLike";
        case core::ContentKind::StructuredBinary: return "StructuredBinary";
        case core::ContentKind::MostlyZero: return "MostlyZero";
        case core::ContentKind::RepeatedPattern: return "RepeatedPattern";
        case core::ContentKind::CompressedOrEncrypted: return "CompressedOrEncrypted";
    }
    return "Unknown";
}

struct Summary {
    std::size_t total_files{0};
    std::uint64_t total_bytes{0};
    std::size_t healthy_files{0};
    std::size_t flagged_files{0};
    std::size_t io_errors{0};
    std::size_t duplicate_groups{0};
    std::size_t duplicate_files{0};
    std::uint64_t duplicate_bytes{0};
    std::vector<std::pair<std::string, std::size_t>> top_extensions;
};

[[nodiscard]] Summary build_summary(const std::vector<core::FileReport>& reports) {
    Summary summary;
    summary.total_files = reports.size();

    std::unordered_map<std::string, std::size_t> extension_counts;
    std::unordered_map<std::size_t, std::pair<std::size_t, std::uint64_t>> duplicate_groups;

    for (const auto& report : reports) {
        summary.total_bytes += report.size_bytes;

        if (report.status == core::FileStatus::Ok) {
            ++summary.healthy_files;
        } else if (report.status == core::FileStatus::IoError) {
            ++summary.io_errors;
        } else {
            ++summary.flagged_files;
        }

        const std::string extension = report.extension.empty() ? "<none>" : report.extension;
        ++extension_counts[extension];

        if (report.duplicate_group_id != 0U) {
            auto& group = duplicate_groups[report.duplicate_group_id];
            ++group.first;
            group.second += report.size_bytes;
        }
    }

    summary.duplicate_groups = duplicate_groups.size();
    for (const auto& [group_id, group_data] : duplicate_groups) {
        (void)group_id;
        summary.duplicate_files += group_data.first;
        summary.duplicate_bytes += group_data.second;
    }

    summary.top_extensions.assign(extension_counts.begin(), extension_counts.end());
    std::ranges::sort(summary.top_extensions, [](const auto& left, const auto& right) {
        if (left.second != right.second) {
            return left.second > right.second;
        }
        return left.first < right.first;
    });

    return summary;
}

class ConsoleReporter {
public:
    static void print(std::ostream& out, const std::vector<core::FileReport>& reports, std::chrono::milliseconds total_duration) {
        const auto summary = build_summary(reports);

        out << "\n================================================================================\n";
        out << "                                FILE ANALYSIS REPORT                            \n";
        out << "================================================================================\n";

        out << std::fixed << std::setprecision(3);

        for (const auto& report : reports) {
            out << "\nFILE:        " << report.path.string() << '\n';
            out << "EXTENSION:   " << (report.extension.empty() ? "<none>" : report.extension) << '\n';
            out << "SIZE:        " << report.size_bytes << " bytes\n";
            out << "STATUS:      " << status_to_string(report.status) << '\n';
            out << "KIND:        " << content_kind_to_string(report.content_kind) << '\n';
            out << "ENTROPY:     " << report.entropy << " bits/byte\n";
            out << "NULL RATIO:  " << report.null_ratio << '\n';
            out << "PRINTABLE:   " << report.printable_ratio << '\n';
            out << "TAIL ZERO:   " << report.tail_zero_ratio << '\n';
            out << "UNIQUE BYTE: " << report.unique_byte_count << '\n';
            out << "MAX RUN:     " << report.max_byte_run << '\n';
            out << "TIME:        " << report.processing_time.count() << " us\n";

            if (!report.sha256_hex.empty()) {
                out << "SHA256:      " << report.sha256_hex << '\n';
            }

            if (report.duplicate_group_id != 0U) {
                out << "DUPLICATE:   group #" << report.duplicate_group_id
                    << " of " << report.duplicate_group_size << '\n';
            }

            if (!report.findings.empty()) {
                out << "NOTES:       " << report.summary << '\n';
            }

            out << "--------------------------------------------------------------------------------\n";
        }

        out << "\n[ SUMMARY ]\n";
        out << std::left << std::setw(24) << "Total files"      << ": " << summary.total_files << '\n';
        out << std::left << std::setw(24) << "Total bytes"      << ": " << summary.total_bytes << '\n';
        out << std::left << std::setw(24) << "Healthy files"    << ": " << summary.healthy_files << '\n';
        out << std::left << std::setw(24) << "Flagged files"    << ": " << summary.flagged_files << '\n';
        out << std::left << std::setw(24) << "I/O errors"       << ": " << summary.io_errors << '\n';
        out << std::left << std::setw(24) << "Duplicate groups" << ": " << summary.duplicate_groups << '\n';
        out << std::left << std::setw(24) << "Duplicate files"  << ": " << summary.duplicate_files << '\n';
        out << std::left << std::setw(24) << "Duplicate bytes"  << ": " << summary.duplicate_bytes << '\n';
        out << std::left << std::setw(24) << "Execution time"   << ": " << total_duration.count() << " ms\n";

        const std::size_t max_extensions_to_print = std::min<std::size_t>(5U, summary.top_extensions.size());
        if (max_extensions_to_print > 0U) {
            out << "\n[ TOP EXTENSIONS ]\n";
            for (std::size_t i = 0; i < max_extensions_to_print; ++i) {
                out << std::left << std::setw(12) << summary.top_extensions[i].first
                    << ": " << summary.top_extensions[i].second << '\n';
            }
        }

        out << '\n';
    }
};

class JsonReporter {
public:
    static void print(std::ostream& out, const std::vector<core::FileReport>& reports, std::chrono::milliseconds total_duration) {
        const auto summary = build_summary(reports);

        out << "{\n";
        out << "  \"summary\": {\n";
        out << "    \"total_files\": " << summary.total_files << ",\n";
        out << "    \"total_bytes\": " << summary.total_bytes << ",\n";
        out << "    \"healthy_files\": " << summary.healthy_files << ",\n";
        out << "    \"flagged_files\": " << summary.flagged_files << ",\n";
        out << "    \"io_errors\": " << summary.io_errors << ",\n";
        out << "    \"duplicate_groups\": " << summary.duplicate_groups << ",\n";
        out << "    \"duplicate_files\": " << summary.duplicate_files << ",\n";
        out << "    \"duplicate_bytes\": " << summary.duplicate_bytes << ",\n";
        out << "    \"execution_time_ms\": " << total_duration.count() << ",\n";
        out << "    \"top_extensions\": [\n";

        for (std::size_t i = 0; i < summary.top_extensions.size(); ++i) {
            const auto& [extension, count] = summary.top_extensions[i];
            out << "      {\"extension\": \"" << util::json_escape(extension) << "\", \"count\": " << count << "}";
            out << (i + 1U == summary.top_extensions.size() ? "\n" : ",\n");
        }

        out << "    ]\n";
        out << "  },\n";
        out << "  \"reports\": [\n";

        out << std::fixed << std::setprecision(6);

        for (std::size_t i = 0; i < reports.size(); ++i) {
            const auto& report = reports[i];

            out << "    {\n";
            out << "      \"path\": \"" << util::json_escape(report.path.generic_string()) << "\",\n";
            out << "      \"extension\": \"" << util::json_escape(report.extension) << "\",\n";
            out << "      \"size_bytes\": " << report.size_bytes << ",\n";
            out << "      \"sha256\": \"" << util::json_escape(report.sha256_hex) << "\",\n";
            out << "      \"entropy\": " << report.entropy << ",\n";
            out << "      \"null_ratio\": " << report.null_ratio << ",\n";
            out << "      \"printable_ratio\": " << report.printable_ratio << ",\n";
            out << "      \"tail_zero_ratio\": " << report.tail_zero_ratio << ",\n";
            out << "      \"unique_byte_count\": " << report.unique_byte_count << ",\n";
            out << "      \"max_byte_run\": " << report.max_byte_run << ",\n";
            out << "      \"content_kind\": \"" << content_kind_to_string(report.content_kind) << "\",\n";
            out << "      \"status\": \"" << status_to_string(report.status) << "\",\n";
            out << "      \"summary\": \"" << util::json_escape(report.summary) << "\",\n";
            out << "      \"duplicate_group_id\": " << report.duplicate_group_id << ",\n";
            out << "      \"duplicate_group_size\": " << report.duplicate_group_size << ",\n";
            out << "      \"processing_time_us\": " << report.processing_time.count() << ",\n";
            out << "      \"findings\": [";

            for (std::size_t j = 0; j < report.findings.size(); ++j) {
                out << "\"" << util::json_escape(report.findings[j]) << "\"";
                if (j + 1U != report.findings.size()) {
                    out << ", ";
                }
            }

            out << "]\n";
            out << "    }";
            out << (i + 1U == reports.size() ? "\n" : ",\n");
        }

        out << "  ]\n";
        out << "}\n";
    }
};

} // namespace reporting

// ============================================================================
// 8. TESTS
// ============================================================================
namespace tests {

[[noreturn]] void fail(std::string_view message, const std::source_location location = std::source_location::current()) {
    std::ostringstream out;
    out << location.file_name() << ':' << location.line() << " - " << message;
    throw std::runtime_error(out.str());
}

void expect_true(bool condition, std::string_view message, const std::source_location location = std::source_location::current()) {
    if (!condition) {
        fail(message, location);
    }
}

template <typename T, typename U>
void expect_equal(const T& actual, const U& expected, std::string_view message,
                  const std::source_location location = std::source_location::current()) {
    if (!(actual == expected)) {
        fail(message, location);
    }
}

void expect_near(double actual, double expected, double tolerance, std::string_view message,
                 const std::source_location location = std::source_location::current()) {
    if (std::fabs(actual - expected) > tolerance) {
        fail(message, location);
    }
}

class TempDirectory {
public:
    TempDirectory() {
        std::error_code ec;
        const auto base = fs::temp_directory_path(ec);
        if (ec) {
            throw std::runtime_error("failed to get temp directory");
        }

        const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
        for (int attempt = 0; attempt < 100; ++attempt) {
            path_ = base / ("file_analyzer_test_" + std::to_string(seed) + "_" + std::to_string(attempt));
            if (fs::create_directories(path_, ec) && !ec) {
                return;
            }
            ec.clear();
        }

        throw std::runtime_error("failed to create temporary test directory");
    }

    ~TempDirectory() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }

    [[nodiscard]] const fs::path& path() const noexcept {
        return path_;
    }

private:
    fs::path path_;
};

void write_binary_file(const fs::path& path, std::span<const std::uint8_t> bytes) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to create test file: " + path.string());
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out) {
        throw std::runtime_error("failed to write test file: " + path.string());
    }
}

void write_text_file(const fs::path& path, std::string_view text) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to create test file: " + path.string());
    }
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) {
        throw std::runtime_error("failed to write test file: " + path.string());
    }
}

[[nodiscard]] std::string bytes_to_string(std::span<const std::uint8_t> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

void test_sha256_vectors() {
    {
        crypto::Sha256 sha;
        const std::string input;
        sha.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
        expect_equal(
            sha.finish_hex(),
            std::string("e3b0c44298fc1c149afbf4c8996fb924"
                        "27ae41e4649b934ca495991b7852b855"),
            "SHA256 empty string mismatch");
    }

    {
        crypto::Sha256 sha;
        const std::string input = "The quick brown fox jumps over the lazy dog";
        sha.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
        expect_equal(
            sha.finish_hex(),
            std::string("d7a8fbb307d7809469ca9abcb0082e4f"
                        "8d5651e46d3cdb762d02d0bf37c9e592"),
            "SHA256 known vector mismatch");
    }
}

void test_metrics() {
    metrics::ByteStatistics zero_stats;
    std::vector<std::uint8_t> zeroes(1024U, 0U);
    metrics::update(zero_stats, zeroes);
    expect_near(metrics::entropy_bits_per_byte(zero_stats), 0.0, 1e-12, "zero entropy should be 0");
    expect_equal(metrics::unique_byte_count(zero_stats), static_cast<std::size_t>(1U), "unique byte count mismatch");

    metrics::ByteStatistics uniform_stats;
    std::vector<std::uint8_t> uniform(256U);
    for (std::size_t i = 0; i < uniform.size(); ++i) {
        uniform[i] = static_cast<std::uint8_t>(i);
    }
    metrics::update(uniform_stats, uniform);
    expect_true(metrics::entropy_bits_per_byte(uniform_stats) >= 7.99, "uniform entropy should be near 8");
}

void test_stream_analyzer_statuses() {
    core::AnalysisConfig config;

    {
        std::istringstream stream(std::string(), std::ios::binary);
        const auto result = analyzer::StreamAnalyzer::analyze(stream, ".bin", config);
        expect_true(result.has_value(), "empty stream should analyze");
        expect_equal(result.value().status, core::FileStatus::Empty, "empty file status mismatch");
    }

    {
        const std::vector<std::uint8_t> bytes(512U, 0U);
        std::istringstream stream(bytes_to_string(bytes), std::ios::binary);
        const auto result = analyzer::StreamAnalyzer::analyze(stream, ".bin", config);
        expect_true(result.has_value(), "zero stream should analyze");
        expect_equal(result.value().status, core::FileStatus::HighNullBytes, "high null byte status mismatch");
    }

    {
        std::vector<std::uint8_t> bytes;
        for (int i = 0; i < 64; ++i) {
            bytes.push_back('A');
            bytes.push_back('B');
            bytes.push_back('C');
            bytes.push_back('D');
        }
        std::istringstream stream(bytes_to_string(bytes), std::ios::binary);
        const auto result = analyzer::StreamAnalyzer::analyze(stream, ".bin", config);
        expect_true(result.has_value(), "pattern stream should analyze");
        expect_equal(result.value().status, core::FileStatus::RepeatingPattern, "repeating pattern status mismatch");
    }

    {
        const std::string data = "PK\x03\x04""test payload for zip-like content with some variability 12345";
        std::istringstream stream(data, std::ios::binary);
        const auto result = analyzer::StreamAnalyzer::analyze(stream, ".zip", config);
        expect_true(result.has_value(), "zip stream should analyze");
        expect_equal(result.value().status, core::FileStatus::Ok, "valid zip-like magic should pass");
    }

    {
        const std::string data = "not a zip";
        std::istringstream stream(data, std::ios::binary);
        const auto result = analyzer::StreamAnalyzer::analyze(stream, ".zip", config);
        expect_true(result.has_value(), "bad zip stream should analyze");
        expect_equal(result.value().status, core::FileStatus::MagicMismatch, "invalid zip magic should fail");
    }

    {
        std::vector<std::uint8_t> bytes(512U);
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] = static_cast<std::uint8_t>(i % 256U);
        }
        std::istringstream stream(bytes_to_string(bytes), std::ios::binary);
        const auto result = analyzer::StreamAnalyzer::analyze(stream, ".txt", config);
        expect_true(result.has_value(), "high entropy text stream should analyze");
        expect_equal(result.value().status, core::FileStatus::SuspiciousHighEntropyText, "text entropy mismatch");
    }
}

void test_magic_offset_signature() {
    const std::vector<std::uint8_t> mp4 = {
        0x00U, 0x00U, 0x00U, 0x18U, 'f', 't', 'y', 'p',
        'i', 's', 'o', 'm', 0x00U, 0x00U, 0x00U, 0x01U,
        'i', 's', 'o', 'm'
    };

    std::istringstream stream(bytes_to_string(mp4), std::ios::binary);
    const auto result = analyzer::StreamAnalyzer::analyze(stream, ".mp4", core::AnalysisConfig{});
    expect_true(result.has_value(), "mp4 stream should analyze");
    expect_true(result.value().status != core::FileStatus::MagicMismatch, "mp4 offset signature should match");
}

void test_thread_pool_executes_all_tasks() {
    io::ThreadPool pool(4U);
    std::atomic<int> counter{0};
    std::vector<std::future<void>> futures;

    for (int i = 0; i < 100; ++i) {
        futures.push_back(pool.submit([&counter] {
            counter.fetch_add(1, std::memory_order_relaxed);
        }));
    }

    for (auto& future : futures) {
        future.get();
    }

    pool.wait_idle();
    expect_equal(counter.load(std::memory_order_relaxed), 100, "thread pool task count mismatch");
}

void test_directory_scan_and_duplicates() {
    TempDirectory temp;

    write_text_file(temp.path() / "good.zip", "PK\x03\x04payload for a valid zip-like file with mixed bytes 1234567890");
    write_text_file(temp.path() / "bad.zip", "plain text pretending to be a zip");
    write_text_file(temp.path() / "a.txt", "same textual content");
    write_text_file(temp.path() / "b.txt", "same textual content");
    write_binary_file(temp.path() / "empty.bin", {});
    fs::create_directories(temp.path() / "sub");
    write_text_file(temp.path() / "sub" / "nested.txt", "nested file");

    io::ConcurrentFileAnalyzer scanner(core::AnalysisConfig{}, 4U);
    const auto result = scanner.analyze_directory(temp.path(), true);
    expect_true(result.has_value(), "directory scan should succeed");

    const auto& reports = result.value();
    expect_equal(reports.size(), static_cast<std::size_t>(6U), "report count mismatch");

    std::unordered_map<std::string, core::FileReport> by_name;
    for (const auto& report : reports) {
        by_name.emplace(report.path.filename().string(), report);
    }

    expect_equal(by_name.at("good.zip").status, core::FileStatus::Ok, "good zip status mismatch");
    expect_equal(by_name.at("bad.zip").status, core::FileStatus::MagicMismatch, "bad zip status mismatch");
    expect_equal(by_name.at("empty.bin").status, core::FileStatus::Empty, "empty file status mismatch");
    expect_true(by_name.at("a.txt").duplicate_group_id != 0U, "duplicate group should be assigned");
    expect_equal(by_name.at("a.txt").duplicate_group_id, by_name.at("b.txt").duplicate_group_id, "duplicate ids should match");
    expect_true(by_name.count("nested.txt") == 1U, "recursive scan should include nested file");
}

int run_all_tests() {
    struct TestCase {
        std::string_view name;
        void (*function)();
    };

    const std::array<TestCase, 6> tests = {{
        {"SHA256 vectors", test_sha256_vectors},
        {"Metrics", test_metrics},
        {"Stream analyzer statuses", test_stream_analyzer_statuses},
        {"Magic offset signature", test_magic_offset_signature},
        {"Thread pool", test_thread_pool_executes_all_tasks},
        {"Directory scan and duplicates", test_directory_scan_and_duplicates}
    }};

    std::size_t passed = 0;
    std::size_t failed = 0;

    std::cout << "========================================\n";
    std::cout << " Running Internal Diagnostic Test Suite \n";
    std::cout << "========================================\n";

    for (const auto& test : tests) {
        try {
            test.function();
            ++passed;
            std::cout << "[PASS] " << test.name << '\n';
        } catch (const std::exception& ex) {
            ++failed;
            std::cout << "[FAIL] " << test.name << " - " << ex.what() << '\n';
        } catch (...) {
            ++failed;
            std::cout << "[FAIL] " << test.name << " - unknown exception\n";
        }
    }

    std::cout << "\nPassed: " << passed << "\nFailed: " << failed << "\n\n";
    return failed == 0U ? 0 : 1;
}

} // namespace tests

// ============================================================================
// 9. CLI
// ============================================================================
struct AppConfig {
    fs::path target_directory;
    bool has_target_directory{false};
    bool recursive{true};
    bool json_output{false};
    bool fail_on_findings{false};
    bool run_tests{false};
    bool show_help{false};
    std::size_t thread_count{util::default_thread_count()};
    core::AnalysisConfig analysis;
};

void print_usage(const char* program_name) {
    std::cout
        << "Usage: " << program_name << " [options] <directory>\n\n"
        << "Options:\n"
        << "  --help                 Show help and exit\n"
        << "  --test                 Run built-in unit and integration tests\n"
        << "  --no-recursive         Scan only the top-level directory\n"
        << "  --threads <N>          Set worker thread count\n"
        << "  --no-sha256            Disable SHA-256 calculation\n"
        << "  --no-magic             Disable magic number validation\n"
        << "  --no-duplicates        Disable duplicate detection\n"
        << "  --sample-size <N>      Set header sample size in bytes\n"
        << "  --chunk-size <N>       Set stream read chunk size in bytes\n"
        << "  --json                 Emit JSON instead of console text\n"
        << "  --fail-on-findings     Exit with code 2 when any file is flagged or unreadable\n";
}

[[nodiscard]] util::Result<AppConfig, std::string> parse_arguments(int argc, char* argv[]) {
    AppConfig config;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);

        if (arg == "--help" || arg == "-h") {
            config.show_help = true;
        } else if (arg == "--test") {
            config.run_tests = true;
        } else if (arg == "--no-recursive") {
            config.recursive = false;
        } else if (arg == "--json") {
            config.json_output = true;
        } else if (arg == "--fail-on-findings") {
            config.fail_on_findings = true;
        } else if (arg == "--no-sha256") {
            config.analysis.calculate_sha256 = false;
        } else if (arg == "--no-magic") {
            config.analysis.validate_magic_numbers = false;
        } else if (arg == "--no-duplicates") {
            config.analysis.detect_duplicates = false;
        } else if (arg == "--threads") {
            if (i + 1 >= argc) {
                return util::Result<AppConfig, std::string>::failure("missing value for --threads");
            }
            auto parsed = util::parse_unsigned<std::size_t>(argv[++i], "--threads");
            if (!parsed) {
                return util::Result<AppConfig, std::string>::failure(parsed.error());
            }
            config.thread_count = std::max<std::size_t>(1U, parsed.value());
        } else if (arg == "--sample-size") {
            if (i + 1 >= argc) {
                return util::Result<AppConfig, std::string>::failure("missing value for --sample-size");
            }
            auto parsed = util::parse_unsigned<std::size_t>(argv[++i], "--sample-size");
            if (!parsed || parsed.value() == 0U) {
                return util::Result<AppConfig, std::string>::failure(
                    parsed ? std::string("--sample-size must be greater than zero") : parsed.error());
            }
            config.analysis.head_sample_size = parsed.value();
        } else if (arg == "--chunk-size") {
            if (i + 1 >= argc) {
                return util::Result<AppConfig, std::string>::failure("missing value for --chunk-size");
            }
            auto parsed = util::parse_unsigned<std::size_t>(argv[++i], "--chunk-size");
            if (!parsed || parsed.value() == 0U) {
                return util::Result<AppConfig, std::string>::failure(
                    parsed ? std::string("--chunk-size must be greater than zero") : parsed.error());
            }
            config.analysis.read_chunk_size = parsed.value();
        } else if (!arg.empty() && arg.front() == '-') {
            return util::Result<AppConfig, std::string>::failure("unknown option: " + std::string(arg));
        } else {
            if (config.has_target_directory) {
                return util::Result<AppConfig, std::string>::failure("multiple target directories specified");
            }
            config.target_directory = fs::path(arg);
            config.has_target_directory = true;
        }
    }

    if (!config.show_help && !config.run_tests && !config.has_target_directory) {
        return util::Result<AppConfig, std::string>::failure("missing target directory");
    }

    return util::Result<AppConfig, std::string>::success(std::move(config));
}

[[nodiscard]] bool has_flagged_or_error_reports(const std::vector<core::FileReport>& reports) noexcept {
    return std::any_of(reports.begin(), reports.end(), [](const core::FileReport& report) {
        return report.status != core::FileStatus::Ok;
    });
}

// ============================================================================
// 10. MAIN
// ============================================================================
// Wrapped so that the same translation unit can also be compiled into the
// Python acceleration library (src/cpp/cie_accel.cpp defines CIE_ACCEL_LIBRARY):
// the library reuses crypto::Sha256 and metrics::ByteStatistics from this file
// instead of maintaining a second, divergent implementation.
#ifndef CIE_ACCEL_LIBRARY
int main(int argc, char* argv[]) {
    const auto config_result = parse_arguments(argc, argv);
    if (!config_result) {
        std::cerr << "Error: " << config_result.error() << "\n\n";
        print_usage(argv[0]);
        return 1;
    }

    AppConfig config = std::move(const_cast<util::Result<AppConfig, std::string>&>(config_result)).value();

    if (config.show_help) {
        print_usage(argv[0]);
        return 0;
    }

    if (config.run_tests) {
        return tests::run_all_tests();
    }

    std::error_code ec;
    if (!fs::exists(config.target_directory, ec) || ec || !fs::is_directory(config.target_directory, ec) || ec) {
        std::cerr << "Error: invalid or inaccessible directory: " << config.target_directory << '\n';
        return 1;
    }

    std::cout << "[INFO] Target directory : " << config.target_directory << '\n';
    std::cout << "[INFO] Recursive scan   : " << (config.recursive ? "yes" : "no") << '\n';
    std::cout << "[INFO] Worker threads   : " << config.thread_count << '\n';

    const auto start = std::chrono::steady_clock::now();

    io::ConcurrentFileAnalyzer analyzer(config.analysis, config.thread_count);
    const auto reports_result = analyzer.analyze_directory(config.target_directory, config.recursive);

    const auto end = std::chrono::steady_clock::now();
    const auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    if (!reports_result) {
        std::cerr << "Error: " << reports_result.error() << '\n';
        return 1;
    }

    const auto& reports = reports_result.value();

    if (config.json_output) {
        reporting::JsonReporter::print(std::cout, reports, total_duration);
    } else {
        reporting::ConsoleReporter::print(std::cout, reports, total_duration);
    }

    if (config.fail_on_findings && has_flagged_or_error_reports(reports)) {
        return 2;
    }

    return 0;
}

#endif // CIE_ACCEL_LIBRARY
