#include "experiments/metrics_collector.hpp"

#include <stdexcept>

namespace experiments {

MetricsCollector::MetricsCollector(const std::string& outputPath, uint64_t seed)
    : _out(outputPath), _seed(seed) {
    if (!_out.is_open()) {
        throw std::runtime_error("MetricsCollector: cannot open " + outputPath);
    }
}

MetricsCollector::~MetricsCollector() {
    flush();
}

void MetricsCollector::writeHeader() {
    _out << "profile,cipher_mode,nonce_mode,detector_enabled,"
         << "scenario,phase,attack_n,frame_idx,"
         << "allowed,reason,quarantined,anomaly_type,"
         << "latency_ns,seed,run_idx\n";
}

void MetricsCollector::append(const MetricRow& row) {
    _out << row.profile << ','
         << row.cipherMode << ','
         << row.nonceMode << ','
         << (row.detectorEnabled ? "true" : "false") << ','
         << row.scenario << ','
         << row.phase << ','
         << row.attackN << ','
         << row.frameIdx << ','
         << (row.allowed ? "true" : "false") << ','
         << row.reason << ','
         << (row.quarantined ? "true" : "false") << ','
         << row.anomalyType << ','
         << row.latencyNs << ','
         << (_seed + row.runIdx) << ','
         << row.runIdx << '\n';
}

void MetricsCollector::flush() {
    _out.flush();
}

}  // namespace experiments
