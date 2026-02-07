#include <access_core/handle_frame.hpp>

namespace access_core {

HandleResult handle_frame(
    std::span<const uint8_t> frame_bytes,
    crypto_lib::aead::SecureAead& server_aead,
    std::unordered_map<uint32_t, protocol::replay::ReplayWindow>& replay_by_reader,
    const HandleFrameConfig& cfg) {

    HandleResult out;

    protocol::frame::Frame f;
    try {
        f = protocol::frame::parse(frame_bytes);
    } catch (...) {
        out.allow = false;
        out.reason = "parse_error";
        return out;
    }

    out.header = f.header;

    protocol::replay::ReplayWindow* window_ptr = nullptr;

    if (cfg.anti_replay_enabled) {
        const size_t win = (cfg.replay_window_size == 0) ? 1 : cfg.replay_window_size;

        auto& window =
            replay_by_reader.try_emplace(f.header.reader_id, protocol::replay::ReplayWindow(win))
                .first->second;

        window_ptr = &window;

        if (window.contains(f.header.seq)) {
            out.allow = false;
            out.reason = "replay";
            return out;
        }
    }

    const auto aad_vec = f.header.to_bytes();
    const std::span<const uint8_t> aad(aad_vec.data(), aad_vec.size());

    try {
        crypto_lib::aead::Tag tag{};
        tag.v = f.tag.v;

        out.plaintext = server_aead.open_with_nonce(f.ct, tag, aad, f.header.nonce);
        out.allow = true;
        out.reason = "ok";

        if (cfg.anti_replay_enabled && window_ptr) {
            window_ptr->remember(f.header.seq);
        }
        return out;
    } catch (...) {
        out.allow = false;
        out.reason = "decrypt_failed";
        return out;
    }
}


}  // namespace access_core
