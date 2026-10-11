#define _GNU_SOURCE
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eigrp_types.h"
#include "eigrp_const.h"
#include "eigrp_structs.h"
#include "eigrp_log.h"
#include "eigrp_interface.h"
#include "eigrp_neighbor.h"
#include "eigrp_packet.h"
#include "eigrp_auth.h"
#include "eigrp_md5.h"
#include "eigrp_sha256.h"
#include "eigrp_sys.h"
#include "eigrp_instance.h"
#include "eigrp.h"

static unsigned char srl_zeropad[16] = {0};

static bool srl_auth_sequence_newer(uint32_t received_wire, uint32_t stored_wire)
{
    uint32_t received = ntohl(received_wire);
    uint32_t stored = ntohl(stored_wire);
    uint32_t delta = received - stored;
    return delta != 0 && delta < 0x80000000U;
}

static bool srl_auth_key_get(eigrp_intf_t *ei, uint32_t *key_id,
                             char *key, size_t key_size)
{
    if (!ei || !key || key_size == 0)
        return false;

    if (ei->params.auth_password) {
        size_t len = strlen(ei->params.auth_password);
        if (len >= key_size)
            return false;
        memcpy(key, ei->params.auth_password, len + 1);
        if (key_id)
            *key_id = 0;
        return true;
    }

    return ei->params.auth_keychain
           && eigrp_sys_auth_key_lookup(ei->params.auth_keychain, key_id,
                                        key, key_size);
}

static bool srl_auth_sha256_source(eigrp_intf_t *ei, eigrp_nbr_t *nbr,
                                   char *text, size_t text_size)
{
    const void *address;
    int af;

    if (nbr) {
        af = nbr->src.afi;
        address = (af == AF_INET6) ? (const void *)&nbr->src.ip.v6
                                   : (const void *)&nbr->src.ip.v4;
    } else if (ei && ei->address.address.afi == EIGRP_AFI_IPV6) {
        af = AF_INET6;
        address = ei->address.address.bytes;
    } else if (ei) {
        af = AF_INET;
        address = ei->address.address.bytes;
    } else {
        return false;
    }

    return inet_ntop(af, address, text, text_size) != NULL;
}

int __wrap_eigrp_make_md5_digest(eigrp_intf_t *ei, eigrp_stream_t *s, uint8_t flags)
{
    char key_string[PLAINTEXT_LENGTH + 1] = {0};
    uint32_t key_id = 0;
    unsigned char digest[EIGRP_AUTH_TYPE_MD5_LEN];
    eigrp_md5_ctx_t ctx;
    uint8_t *ibuf;
    size_t backup_get, backup_end;
    struct TLV_MD5_Authentication_Type *auth_TLV;

    ibuf = s->data;
    backup_end = s->endp;
    backup_get = s->getp;

    auth_TLV = eigrp_auth_tlv_md5_create();

    eigrp_stream_set_getp(s, EIGRP_HEADER_LEN);
    eigrp_stream_get(auth_TLV, s, EIGRP_AUTH_MD5_TLV_SIZE);
    eigrp_stream_set_getp(s, backup_get);

    if (!srl_auth_key_get(ei, &key_id, key_string, sizeof(key_string))) {
        eigrp_auth_tlv_md5_delete(auth_TLV);
        explicit_bzero(key_string, sizeof(key_string));
        return EIGRP_AUTH_TYPE_NONE;
    }

    memset(&ctx, 0, sizeof(ctx));
    eigrp_md5_init(&ctx);

    if (flags & EIGRP_AUTH_BASIC_HELLO_FLAG) {
        eigrp_md5_update(&ctx, ibuf, EIGRP_MD5_BASIC_COMPUTE);
        eigrp_md5_update(&ctx, key_string, strlen(key_string));
        if (strlen(key_string) < 16)
            eigrp_md5_update(&ctx, srl_zeropad, 16 - strlen(key_string));
    } else if (flags & EIGRP_AUTH_UPDATE_INIT_FLAG) {
        eigrp_md5_update(&ctx, ibuf, EIGRP_MD5_UPDATE_INIT_COMPUTE);
    } else if (flags & EIGRP_AUTH_UPDATE_FLAG) {
        eigrp_md5_update(&ctx, ibuf, EIGRP_MD5_BASIC_COMPUTE);
        eigrp_md5_update(&ctx, key_string, strlen(key_string));
        if (strlen(key_string) < 16)
            eigrp_md5_update(&ctx, srl_zeropad, 16 - strlen(key_string));
        if (backup_end > (EIGRP_HEADER_LEN + EIGRP_AUTH_MD5_TLV_SIZE)) {
            eigrp_md5_update(&ctx,
                      ibuf + (EIGRP_HEADER_LEN + EIGRP_AUTH_MD5_TLV_SIZE),
                      backup_end - 20 - (EIGRP_HEADER_LEN + EIGRP_AUTH_MD5_TLV_SIZE));
        }
    }

    eigrp_md5_final(digest, &ctx);

    memcpy(auth_TLV->digest, digest, EIGRP_AUTH_TYPE_MD5_LEN);

    eigrp_stream_set_endp(s, EIGRP_HEADER_LEN);
    eigrp_stream_put(s, auth_TLV, EIGRP_AUTH_MD5_TLV_SIZE);
    eigrp_stream_set_endp(s, backup_end);

    eigrp_auth_tlv_md5_delete(auth_TLV);
    explicit_bzero(key_string, sizeof(key_string));
    return EIGRP_AUTH_TYPE_MD5_LEN;
}

int __wrap_eigrp_check_md5_digest(eigrp_stream_t *s,
                                  struct TLV_MD5_Authentication_Type *authTLV,
                                  eigrp_nbr_t *nbr, uint8_t flags)
{
    eigrp_md5_ctx_t ctx;
    unsigned char digest[EIGRP_AUTH_TYPE_MD5_LEN];
    unsigned char orig[EIGRP_AUTH_TYPE_MD5_LEN];
    char key_string[PLAINTEXT_LENGTH + 1] = {0};
    uint32_t key_id = 0;
    uint8_t *ibuf;
    size_t backup_end;
    struct TLV_MD5_Authentication_Type *auth_TLV;
    struct eigrp_header *eigrph;
    uint16_t saved_checksum;

    (void)flags;
    if (nbr->crypt_seqnum != 0 &&
        !srl_auth_sequence_newer(authTLV->key_sequence, nbr->crypt_seqnum)) {
        eigrp_log(EIGRP_LOG_WARNING,
            "interface %s: eigrp_check_md5 bad sequence %d (expect %d)",
            eigrp_intf_name_string(nbr->ei), ntohl(authTLV->key_sequence),
            ntohl(nbr->crypt_seqnum));
        return 0;
    }

    eigrph = (struct eigrp_header *)s->data;
    saved_checksum = eigrph->checksum;
    eigrph->checksum = 0;

    auth_TLV = (struct TLV_MD5_Authentication_Type *)(s->data + EIGRP_HEADER_LEN);
    memcpy(orig, auth_TLV->digest, EIGRP_AUTH_TYPE_MD5_LEN);
    memset(digest, 0, EIGRP_AUTH_TYPE_MD5_LEN);
    memset(auth_TLV->digest, 0, EIGRP_AUTH_TYPE_MD5_LEN);

    ibuf = s->data;
    backup_end = s->endp;
    key_id = authTLV ? ntohl(authTLV->key_id) : 0;

    if (!srl_auth_key_get(nbr->ei, &key_id, key_string, sizeof(key_string))) {
        eigrp_log(EIGRP_LOG_WARNING,
            "Interface %s: Expected key value not found in config",
            nbr->ei->name);
        memcpy(auth_TLV->digest, orig, EIGRP_AUTH_TYPE_MD5_LEN);
        eigrph->checksum = saved_checksum;
        explicit_bzero(key_string, sizeof(key_string));
        return 0;
    }

    memset(&ctx, 0, sizeof(ctx));
    eigrp_md5_init(&ctx);

    if (flags & EIGRP_AUTH_BASIC_HELLO_FLAG) {
        eigrp_md5_update(&ctx, ibuf, EIGRP_MD5_BASIC_COMPUTE);
        eigrp_md5_update(&ctx, key_string, strlen(key_string));
        if (strlen(key_string) < 16)
            eigrp_md5_update(&ctx, srl_zeropad, 16 - strlen(key_string));
    } else if (flags & EIGRP_AUTH_UPDATE_INIT_FLAG) {
        eigrp_md5_update(&ctx, ibuf, EIGRP_MD5_UPDATE_INIT_COMPUTE);
    } else if (flags & EIGRP_AUTH_UPDATE_FLAG) {
        eigrp_md5_update(&ctx, ibuf, EIGRP_MD5_BASIC_COMPUTE);
        eigrp_md5_update(&ctx, key_string, strlen(key_string));
        if (strlen(key_string) < 16)
            eigrp_md5_update(&ctx, srl_zeropad, 16 - strlen(key_string));
        if (backup_end > (EIGRP_HEADER_LEN + EIGRP_AUTH_MD5_TLV_SIZE)) {
            eigrp_md5_update(&ctx,
                      ibuf + (EIGRP_HEADER_LEN + EIGRP_AUTH_MD5_TLV_SIZE),
                      backup_end - 20 - (EIGRP_HEADER_LEN + EIGRP_AUTH_MD5_TLV_SIZE));
        }
    }

    eigrp_md5_final(digest, &ctx);

    memcpy(auth_TLV->digest, orig, EIGRP_AUTH_TYPE_MD5_LEN);
    eigrph->checksum = saved_checksum;

    int match = (memcmp(orig, digest, EIGRP_AUTH_TYPE_MD5_LEN) == 0);
    explicit_bzero(key_string, sizeof(key_string));
    if (!match) {
        eigrp_log(EIGRP_LOG_WARNING, "interface %s: eigrp_check_md5 checksum mismatch",
              eigrp_intf_name_string(nbr->ei));
        return 0;
    }

    nbr->crypt_seqnum = authTLV->key_sequence;
    return 1;
}

int __wrap_eigrp_make_sha256_digest(eigrp_intf_t *ei, eigrp_stream_t *s, uint8_t flags)
{
    char key_string[PLAINTEXT_LENGTH + 1] = {0};
    uint32_t key_id = 0;
    char source_ip[INET6_ADDRSTRLEN] = {0};
    unsigned char digest[EIGRP_AUTH_TYPE_SHA256_LEN];
    unsigned char key_buffer[1 + PLAINTEXT_LENGTH + INET6_ADDRSTRLEN] = {0};
    eigrp_hmac_sha256_ctx_t ctx;
    size_t backup_get, backup_end, key_len;
    struct TLV_SHA256_Authentication_Type *auth_tlv;

    (void)flags;
    if (!ei || !s || s->endp < EIGRP_HEADER_LEN + EIGRP_AUTH_SHA256_TLV_SIZE)
        return 0;
    backup_end = s->endp;
    backup_get = s->getp;
    auth_tlv = eigrp_auth_tlv_sha256_create();
    if (!auth_tlv)
        return 0;

    eigrp_stream_set_getp(s, EIGRP_HEADER_LEN);
    eigrp_stream_get(auth_tlv, s, EIGRP_AUTH_SHA256_TLV_SIZE);
    eigrp_stream_set_getp(s, backup_get);
    if (!srl_auth_key_get(ei, &key_id, key_string, sizeof(key_string))
        || !srl_auth_sha256_source(ei, NULL, source_ip, sizeof(source_ip))) {
        eigrp_auth_tlv_sha256_delete(auth_tlv);
        explicit_bzero(key_string, sizeof(key_string));
        return 0;
    }

    memset(auth_tlv->digest, 0, sizeof(auth_tlv->digest));
    eigrp_stream_set_endp(s, EIGRP_HEADER_LEN);
    eigrp_stream_put(s, auth_tlv, EIGRP_AUTH_SHA256_TLV_SIZE);
    eigrp_stream_set_endp(s, backup_end);

    key_buffer[0] = '\n';
    key_len = strlen(key_string);
    memcpy(key_buffer + 1, key_string, key_len);
    memcpy(key_buffer + 1 + key_len, source_ip, strlen(source_ip));
    eigrp_hmac_sha256_init(&ctx, key_buffer, 1 + key_len + strlen(source_ip));
    eigrp_hmac_sha256_update(&ctx, s->data, backup_end);
    eigrp_hmac_sha256_final(digest, &ctx);

    memcpy(auth_tlv->digest, digest, sizeof(digest));
    eigrp_stream_set_endp(s, EIGRP_HEADER_LEN);
    eigrp_stream_put(s, auth_tlv, EIGRP_AUTH_SHA256_TLV_SIZE);
    eigrp_stream_set_endp(s, backup_end);
    eigrp_auth_tlv_sha256_delete(auth_tlv);
    explicit_bzero(key_string, sizeof(key_string));
    explicit_bzero(key_buffer, sizeof(key_buffer));
    return EIGRP_AUTH_TYPE_SHA256_LEN;
}

int __wrap_eigrp_check_sha256_digest(eigrp_stream_t *s,
                                     struct TLV_SHA256_Authentication_Type *authTLV,
                                     eigrp_nbr_t *nbr, uint8_t flags)
{
    char key_string[PLAINTEXT_LENGTH + 1] = {0};
    char source_ip[INET6_ADDRSTRLEN] = {0};
    unsigned char digest[EIGRP_AUTH_TYPE_SHA256_LEN];
    unsigned char original[EIGRP_AUTH_TYPE_SHA256_LEN];
    unsigned char key_buffer[1 + PLAINTEXT_LENGTH + INET6_ADDRSTRLEN] = {0};
    eigrp_hmac_sha256_ctx_t ctx;
    struct eigrp_header *header;
    uint32_t key_id = 0;
    uint16_t saved_checksum;
    size_t key_len;
    int valid;

    (void)flags;
    if (!s || !authTLV || !nbr || !nbr->ei
        || s->endp < EIGRP_HEADER_LEN + EIGRP_AUTH_SHA256_TLV_SIZE)
        return 0;
    if (ntohs(authTLV->type) != EIGRP_TLV_AUTH
        || ntohs(authTLV->length) != EIGRP_AUTH_SHA256_TLV_SIZE
        || ntohs(authTLV->auth_type) != EIGRP_AUTH_TYPE_SHA256
        || ntohs(authTLV->auth_length) != EIGRP_AUTH_TYPE_SHA256_LEN)
        return 0;
    if (nbr->crypt_seqnum != 0 &&
        !srl_auth_sequence_newer(authTLV->key_sequence, nbr->crypt_seqnum))
        return 0;
    key_id = authTLV ? ntohl(authTLV->key_id) : 0;
    if (!srl_auth_key_get(nbr->ei, &key_id, key_string, sizeof(key_string))
        || !srl_auth_sha256_source(nbr->ei, nbr, source_ip, sizeof(source_ip))) {
        explicit_bzero(key_string, sizeof(key_string));
        return 0;
    }

    header = (struct eigrp_header *)s->data;
    saved_checksum = header->checksum;
    header->checksum = 0;
    memcpy(original, authTLV->digest, sizeof(original));
    memset(authTLV->digest, 0, sizeof(authTLV->digest));

    key_buffer[0] = '\n';
    key_len = strlen(key_string);
    memcpy(key_buffer + 1, key_string, key_len);
    memcpy(key_buffer + 1 + key_len, source_ip, strlen(source_ip));
    eigrp_hmac_sha256_init(&ctx, key_buffer, 1 + key_len + strlen(source_ip));
    eigrp_hmac_sha256_update(&ctx, s->data, s->endp);
    eigrp_hmac_sha256_final(digest, &ctx);

    memcpy(authTLV->digest, original, sizeof(original));
    header->checksum = saved_checksum;
    valid = memcmp(original, digest, sizeof(original)) == 0;
    if (valid)
        nbr->crypt_seqnum = authTLV->key_sequence;
    explicit_bzero(key_string, sizeof(key_string));
    explicit_bzero(key_buffer, sizeof(key_buffer));
    return valid;
}

uint16_t __wrap_eigrp_auth_tlv_md5_encode(eigrp_stream_t *s, eigrp_intf_t *ei)
{
    char key_string[PLAINTEXT_LENGTH + 1] = {0};
    uint32_t key_id = 0;
    struct TLV_MD5_Authentication_Type *authTLV;

    authTLV = eigrp_auth_tlv_md5_create();
    authTLV->type = htons(EIGRP_TLV_AUTH);
    authTLV->length = htons(EIGRP_AUTH_MD5_TLV_SIZE);
    authTLV->auth_type = htons(EIGRP_AUTH_TYPE_MD5);
    authTLV->auth_length = htons(EIGRP_AUTH_TYPE_MD5_LEN);
    authTLV->key_sequence = htonl(++ei->crypt_seqnum);
    memset(authTLV->Nullpad, 0, sizeof(authTLV->Nullpad));

    if (srl_auth_key_get(ei, &key_id, key_string, sizeof(key_string))) {
        authTLV->key_id = htonl(key_id);
        memset(authTLV->digest, 0, EIGRP_AUTH_TYPE_MD5_LEN);
        eigrp_stream_put(s, authTLV, sizeof(struct TLV_MD5_Authentication_Type));
        eigrp_auth_tlv_md5_delete(authTLV);
        explicit_bzero(key_string, sizeof(key_string));
        return EIGRP_AUTH_MD5_TLV_SIZE;
    }

    eigrp_auth_tlv_md5_delete(authTLV);
    explicit_bzero(key_string, sizeof(key_string));
    return 0;
}

uint16_t __wrap_eigrp_auth_tlv_sha256_encode(eigrp_stream_t *s, eigrp_intf_t *ei)
{
    char key_string[PLAINTEXT_LENGTH + 1] = {0};
    uint32_t key_id = 0;
    struct TLV_SHA256_Authentication_Type *authTLV;

    authTLV = eigrp_auth_tlv_sha256_create();
    authTLV->type = htons(EIGRP_TLV_AUTH);
    authTLV->length = htons(EIGRP_AUTH_SHA256_TLV_SIZE);
    authTLV->auth_type = htons(EIGRP_AUTH_TYPE_SHA256);
    authTLV->auth_length = htons(EIGRP_AUTH_TYPE_SHA256_LEN);
    authTLV->key_sequence = htonl(++ei->crypt_seqnum);
    memset(authTLV->Nullpad, 0, sizeof(authTLV->Nullpad));

    if (srl_auth_key_get(ei, &key_id, key_string, sizeof(key_string))) {
        authTLV->key_id = 0;
        memset(authTLV->digest, 0, EIGRP_AUTH_TYPE_SHA256_LEN);
        eigrp_stream_put(s, authTLV, sizeof(struct TLV_SHA256_Authentication_Type));
        eigrp_auth_tlv_sha256_delete(authTLV);
        explicit_bzero(key_string, sizeof(key_string));
        return EIGRP_AUTH_SHA256_TLV_SIZE;
    }

    eigrp_auth_tlv_sha256_delete(authTLV);
    explicit_bzero(key_string, sizeof(key_string));
    return 0;
}

void __wrap_eigrp_sys_intf_update(eigrp_vrf_id_t vrf_id, const eigrp_intf_runtime_state_t *state)
{
    if (!state || !eigrp_process.virt_router)
        return;

    pthread_mutex_lock(&eigrp_process.hierarchy_lock);
    eigrp_list_item_t *vr_node, *af_node;
    eigrp_virt_router_t *virt_router;
    eigrp_instance_t *eigrp;
    for (EIGRP_LIST_ITERATE_RO(eigrp_process.virt_router, vr_node, virt_router)) {
        for (EIGRP_LIST_ITERATE_RO(virt_router->af_instance, af_node, eigrp)) {
            if (eigrp->vrf_id != vrf_id || eigrp->shutdown
                || eigrp->af_vectors.afi != state->address.address.afi)
                continue;
            (void)eigrp_instance_intf_update_event_enqueue(eigrp, state);
        }
    }
    pthread_mutex_unlock(&eigrp_process.hierarchy_lock);
}
