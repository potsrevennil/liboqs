// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_UOV_H
#define OQS_SIG_UOV_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_uov_ov_is)
#define OQS_SIG_uov_ov_is_length_public_key 412160
#define OQS_SIG_uov_ov_is_length_secret_key 348704
#define OQS_SIG_uov_ov_is_length_signature 96

OQS_SIG *OQS_SIG_uov_ov_is_new(void);
OQS_API OQS_STATUS OQS_SIG_uov_ov_is_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_uov_ov_is_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_uov_ov_is_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_uov_ov_is_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_uov_ov_is_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#endif
