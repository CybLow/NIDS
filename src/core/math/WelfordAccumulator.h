#pragma once

/// Online statistics accumulator using Welford's algorithm.
///
/// Computes running mean, variance, standard deviation, min, max, and sum
/// in O(1) space per update.  Suitable for streaming statistics on packet
/// lengths, inter-arrival times, and any per-flow metric.
///
/// Reference: Welford, B.P. (1962), "Note on a method for calculating
/// corrected sums of squares and products", Technometrics 4(3):419-420.
///
/// Lives in core/ because it is a pure math utility with zero platform
/// or framework dependencies.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>

namespace nids::core {

/**
 * Online statistics accumulator using Welford's algorithm.
 *
 * Computes running mean, variance, standard deviation, min, max, and sum
 * in O(1) space per update.  Replaces per-packet vectors that previously
 * stored all values for offline statistics computation (~7 KB per flow).
 */
struct WelfordAccumulator {
  std::uint64_t n = 0;
  double mean_ = 0.0;
  double m2_ = 0.0;   ///< Sum of squared deviations from the running mean.
  double sum_ = 0.0;
  double min_ = std::numeric_limits<double>::max();
  double max_ = std::numeric_limits<double>::lowest();

  /** Feed a new observation. */
  void update(double x) noexcept {
    ++n;
    sum_ += x;
    if (n == 1) {
      min_ = max_ = x;
    } else {
      min_ = std::min(min_, x);
      max_ = std::max(max_, x);
    }
    double delta = x - mean_;
    mean_ += delta / static_cast<double>(n);
    double delta2 = x - mean_;
    m2_ += delta * delta2;
  }

  [[nodiscard]] double mean() const noexcept { return n > 0 ? mean_ : 0.0; }
  [[nodiscard]] double sum() const noexcept { return sum_; }
  [[nodiscard]] double min() const noexcept {
    return n > 0 ? min_ : 0.0;
  }
  [[nodiscard]] double max() const noexcept {
    return n > 0 ? max_ : 0.0;
  }

  /** Population variance (divide by N). */
  [[nodiscard]] double populationVariance() const noexcept {
    return n > 0 ? m2_ / static_cast<double>(n) : 0.0;
  }

  /** Sample variance (divide by N-1, Bessel's correction). */
  [[nodiscard]] double sampleVariance() const noexcept {
    return n > 1 ? m2_ / static_cast<double>(n - 1) : 0.0;
  }

  /** Sample standard deviation (sqrt of sample variance, N-1 denominator).
   *
   * Uses sample variance (Bessel's correction, divide by N-1) to match the
   * Python training pipeline (scripts/ml/preprocess.py _stddev() function).
   * The LSNM2024 model was trained with sample stddev — the C++ inference
   * extractor MUST use the same convention.
   */
  [[nodiscard]] double stddev() const noexcept {
    return std::sqrt(sampleVariance());
  }
};

} // namespace nids::core
