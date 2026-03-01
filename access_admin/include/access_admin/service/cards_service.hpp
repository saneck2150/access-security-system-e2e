#pragma once

//! @file cards_service.hpp
//! Service for card management.

#include <cstdint>
#include <optional>
#include <string>

#include <access_admin/service/service_types.hpp>

namespace admin {
struct AppState;
}

namespace admin::service {

//! Lists all cards with pagination.
//! @param [in,out] app Application state.
//! @param [in] limit Maximum number of cards to return.
//! @param [in] offset Offset for pagination.
//! @return ServiceResult with cards array.
ServiceResult listCards(AppState& app, size_t limit, size_t offset);

//! Creates or updates a card.
//! @param [in,out] app Application state.
//! @param [in] card_id Card identifier (plain text).
//! @param [in] role Role to assign.
//! @param [in] key_version Optional key version override.
//! @return ServiceResult with ok and card_hmac.
ServiceResult upsertCard(AppState& app,
                         const std::string& card_id,
                         const std::string& role,
                         std::optional<uint32_t> key_version);

//! Deletes a card by its HMAC.
//! @param [in,out] app Application state.
//! @param [in] card_hmac HMAC of the card to delete.
//! @return ServiceResult indicating success.
ServiceResult deleteCard(AppState& app, const std::string& card_hmac);

}  // namespace admin::service
