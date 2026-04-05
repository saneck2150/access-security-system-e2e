#pragma once

//! @file metrics_collector.hpp
//! CSV metrics output for experiment scenarios.

#include <cstdint>
#include <fstream>
#include <string>

namespace experiments {

//! Single row of experiment output data.
struct MetricRow {
    std::string profile;
    std::string cipherMode;
    std::string nonceMode;
    bool detectorEnabled = false;
    std::string scenario;
    std::string phase;           //!< "warmup", "baseline", "attack"
    uint32_t attackN = 0;        //!< Current attack-step count (0 for baseline/warmup).
    uint32_t frameIdx = 0;       //!< Frame index within phase.
    bool allowed = false;
    std::string reason;
    bool quarantined = false;
    std::string anomalyType;
    uint64_t latencyNs = 0;
    uint32_t runIdx = 0;        //!< Repetition index (S6 uses 0..N-1, others always 0).
};

//! Collects per-frame experiment metrics and writes CSV.
class MetricsCollector {
  public:
    //! @param [in] outputPath CSV output file path.
    //! @param [in] seed       Global experiment seed.
    MetricsCollector(const std::string& outputPath, uint64_t seed);

    ~MetricsCollector();

    //! Writes the CSV header line.
    void writeHeader();

    //! Appends one metric row.
    void append(const MetricRow& row);

    //! Flushes the output stream.
    void flush();

  private:
    std::ofstream _out;
    uint64_t _seed;
};

}  // namespace experiments
