#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "eigrp_types.h"
#include "eigrp_const.h"
#include "eigrp_structs.h"
#include "eigrp_sys.h"
#include "eigrp_instance.h"
#include "eigrp_table.h"
#include "eigrp_topology.h"
#include "eigrp_metric.h"
#include "eigrp_fsm.h"
#include "eigrp_packet.h"
#include "eigrp_prefix.h"
#include "eigrp_interface.h"
#include "eigrp_neighbor.h"
#include "eigrp_eventlog.h"
#include "eigrp_filter.h"
#include "eigrp_log.h"
#include "eigrp.h"

extern bool __real_eigrp_nbr_prefix_admit(eigrp_instance_t *runtime, eigrp_nbr_t *neighbor,
                                          const eigrp_prefix_t *prefix);

static bool srl_prefix_is_query_retained_passive(const eigrp_prefix_descriptor_t *prefix)
{
    return prefix
           && prefix->state == EIGRP_FSM_STATE_PASSIVE
           && prefix->distance == EIGRP_MAX_METRIC
           && prefix->fdistance == EIGRP_MAX_METRIC
           && prefix->reported_metric.delay == EIGRP_MAX_METRIC;
}

static bool srl_prefix_has_active_route(eigrp_prefix_descriptor_t *pfx)
{
    if (!pfx || pfx->distance == EIGRP_MAX_METRIC || pfx->fdistance == EIGRP_MAX_METRIC)
        return false;
    eigrp_route_descriptor_t *best = eigrp_topology_route_read(pfx);
    if (!best || best->distance == EIGRP_MAX_METRIC || best->metric.delay == EIGRP_MAX_METRIC)
        return false;
    return (best->flags & (EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG |
                           EIGRP_ROUTE_DESCRIPTOR_FSUCCESSOR_FLAG)) != 0;
}

static uint32_t srl_active_topology_prefix_count(eigrp_instance_t *runtime)
{
    eigrp_table_node_t *node;
    uint32_t count = 0;

    if (!runtime || !runtime->topology_table)
        return 0;
    for (node = eigrp_table_first(runtime->topology_table); node;
         node = eigrp_table_next(node)) {
        if (srl_prefix_has_active_route(node->info))
            count++;
    }
    return count;
}

static void srl_prune_other_query_retained_routes(eigrp_instance_t *eigrp,
                                                  eigrp_prefix_descriptor_t *prefix,
                                                  eigrp_nbr_t *keep_nbr)
{
    if (!eigrp || !prefix)
        return;
    for (unsigned int q = 0; q < 2; q++) {
        eigrp_list_t *routes = eigrp_topology_route_queue(prefix, q);
        eigrp_list_item_t *node, *nnode;
        eigrp_route_descriptor_t *r;
        for (EIGRP_LIST_ITERATE(routes, node, nnode, r)) {
            if (r && r->adv_router != keep_nbr && r->flags == 0)
                eigrp_route_descriptor_delete(eigrp, prefix, r);
        }
    }
}

bool __wrap_eigrp_topology_prefix_admit(eigrp_instance_t *runtime,
                                        const eigrp_prefix_t *prefix)
{
    eigrp_af_config_t *af;
    const eigrp_prefix_limit_t *limit;
    eigrp_prefix_descriptor_t *existing;

    if (!runtime || !prefix)
        return false;
    if (runtime->eigrp_pfxlimits_af_state)
        return false;
    existing = eigrp_topology_table_lookup(runtime->topology_table, prefix);
    if (srl_prefix_has_active_route(existing))
        return true;
    af = eigrp_af_config_runtime_read(runtime);
    if (!af || !af->topology_maximum_prefix_configured)
        return true;
    limit = &af->topology_maximum_prefix;
    uint32_t count = srl_active_topology_prefix_count(runtime);
    if (eigrp_prefix_limit_threshold_crossed(limit, count))
        eigrp_log(EIGRP_LOG_WARNING,
                  "EIGRP topology maximum-prefix threshold reached (%u/%u)",
                  count + 1U, limit->maximum);
    if (!limit->warning_only && count >= limit->maximum) {
        if (existing && srl_prefix_is_query_retained_passive(existing)) {
            srl_prune_other_query_retained_routes(runtime, existing, NULL);
            eigrp_update_topology_table_prefix(runtime, runtime->topology_table, existing);
        }
        (void)eigrp_eventlog_msg_add(runtime, EIGRP_EVENTLOG_OPCODE_PREFIX_LIMIT_REJECT,
                                     prefix, EIGRP_EVENTLOG_PREFIX_LIMIT_TOPOLOGY,
                                     count + 1U, limit->maximum, 0);
        return false;
    }
    return true;
}

static _Thread_local eigrp_packet_decoder_t srl_saved_update_decoder = NULL;
static _Thread_local eigrp_packet_decoder_t srl_saved_query_decoder = NULL;
static _Thread_local bool srl_in_unreachable_update = false;

bool __wrap_eigrp_nbr_prefix_admit(eigrp_instance_t *runtime, eigrp_nbr_t *neighbor,
                                   const eigrp_prefix_t *prefix)
{
    if (srl_in_unreachable_update)
        return true;
    return __real_eigrp_nbr_prefix_admit(runtime, neighbor, prefix);
}

static eigrp_route_descriptor_t *srl_update_tlv_decoder_intercept(
    eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
    eigrp_stream_t *pkt, uint16_t pktlen)
{
    srl_in_unreachable_update = false;
    if (!srl_saved_update_decoder)
        return NULL;
    eigrp_route_descriptor_t *route = srl_saved_update_decoder(eigrp, nbr, pkt, pktlen);
    if (!route || !eigrp || !nbr)
        return route;

    bool is_unreachable = (eigrp_metric_calculate(eigrp, route->metric) == EIGRP_MAX_METRIC);
    srl_in_unreachable_update = is_unreachable;

    eigrp_prefix_descriptor_t *prefix =
        eigrp_topology_table_lookup(eigrp->topology_table, &route->dest);
    if (!prefix)
        return route;

    eigrp_route_descriptor_t *topology_route =
        eigrp_prefix_descriptor_lookup(prefix, nbr);
    if (topology_route && nbr->ei)
        topology_route->ei = nbr->ei;

    if (is_unreachable) {
        if (srl_prefix_is_query_retained_passive(prefix)) {
            if (topology_route)
                eigrp_route_descriptor_delete(eigrp, prefix, topology_route);
            eigrp_update_topology_table_prefix(eigrp, eigrp->topology_table, prefix);
            eigrp_topology_route_free(route);
            return NULL;
        }
        return route;
    }

    if (srl_prefix_is_query_retained_passive(prefix))
        srl_prune_other_query_retained_routes(eigrp, prefix, nbr);

    return route;
}

extern void __real_eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
                                        struct eigrp_header *eigrph, eigrp_stream_t *pkt,
                                        eigrp_intf_t *ei, int length);

void __wrap_eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
                                 struct eigrp_header *eigrph, eigrp_stream_t *pkt,
                                 eigrp_intf_t *ei, int length)
{
    eigrp_packet_decoder_t prev_saved = srl_saved_update_decoder;
    eigrp_packet_decoder_t orig_decoder = NULL;
    if (nbr && nbr->decoder && nbr->decoder != srl_update_tlv_decoder_intercept) {
        orig_decoder = nbr->decoder;
        srl_saved_update_decoder = orig_decoder;
        nbr->decoder = srl_update_tlv_decoder_intercept;
    }
    __real_eigrp_update_receive(eigrp, nbr, eigrph, pkt, ei, length);
    srl_in_unreachable_update = false;
    if (nbr && orig_decoder)
        nbr->decoder = orig_decoder;
    srl_saved_update_decoder = prev_saved;
}

static eigrp_route_descriptor_t *srl_query_tlv_decoder_intercept(
    eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
    eigrp_stream_t *pkt, uint16_t pktlen)
{
    if (!srl_saved_query_decoder)
        return NULL;
    eigrp_route_descriptor_t *route = srl_saved_query_decoder(eigrp, nbr, pkt, pktlen);
    if (!route || !eigrp || !nbr)
        return route;

    eigrp_prefix_descriptor_t *prefix =
        eigrp_topology_table_lookup(eigrp->topology_table, &route->dest);
    if (prefix && srl_prefix_is_query_retained_passive(prefix)) {
        bool poisoned_or_denied =
            (route->metric.delay == EIGRP_MAX_METRIC
             || route->metric.delay == EIGRP_METRIC_MAX
             || (nbr->ei && eigrp_filter_prefix_update(eigrp, nbr->ei, EIGRP_FILTER_IN, &route->dest)));
        if (poisoned_or_denied) {
            eigrp_route_descriptor_t *topology_route =
                eigrp_prefix_descriptor_lookup(prefix, nbr);
            if (topology_route)
                eigrp_route_descriptor_delete(eigrp, prefix, topology_route);
            eigrp_update_topology_table_prefix(eigrp, eigrp->topology_table, prefix);
        }
    }
    return route;
}

extern void __real_eigrp_query_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
                                       struct eigrp_header *eigrph, eigrp_stream_t *pkt,
                                       eigrp_intf_t *ei, int length);

void __wrap_eigrp_query_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
                                struct eigrp_header *eigrph, eigrp_stream_t *pkt,
                                eigrp_intf_t *ei, int length)
{
    eigrp_packet_decoder_t prev_saved = srl_saved_query_decoder;
    eigrp_packet_decoder_t orig_decoder = NULL;
    if (nbr && nbr->decoder && nbr->decoder != srl_query_tlv_decoder_intercept) {
        orig_decoder = nbr->decoder;
        srl_saved_query_decoder = orig_decoder;
        nbr->decoder = srl_query_tlv_decoder_intercept;
    }
    __real_eigrp_query_receive(eigrp, nbr, eigrph, pkt, ei, length);
    if (nbr && orig_decoder)
        nbr->decoder = orig_decoder;
    srl_saved_query_decoder = prev_saved;
}

extern void __real_eigrp_topology_neighbor_down(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr);

void __wrap_eigrp_topology_neighbor_down(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr)
{
    if (eigrp && eigrp->topology_table && nbr) {
        eigrp_table_node_t *rn, *next_rn;
        for (rn = eigrp_table_first(eigrp->topology_table); rn; rn = next_rn) {
            next_rn = eigrp_table_next(rn);
            eigrp_prefix_descriptor_t *pe = rn->info;
            if (!pe || !srl_prefix_is_query_retained_passive(pe))
                continue;
            eigrp_route_descriptor_t *route = eigrp_prefix_descriptor_lookup(pe, nbr);
            if (route) {
                eigrp_route_descriptor_delete(eigrp, pe, route);
                eigrp_update_topology_table_prefix(eigrp, eigrp->topology_table, pe);
            }
        }
    }

    __real_eigrp_topology_neighbor_down(eigrp, nbr);
}

extern void __real_eigrp_nbr_codec_select(eigrp_nbr_t *nbr, uint8_t tlv_version);
extern void __real_eigrp_nbr_codec_update(eigrp_instance_t *eigrp);

static __thread bool srl_in_codec_update = false;

void __wrap_eigrp_nbr_codec_select(eigrp_nbr_t *nbr, uint8_t tlv_version)
{
    uint8_t old_version = nbr ? nbr->tlv_version : 0;
    __real_eigrp_nbr_codec_select(nbr, tlv_version);
    if (!srl_in_codec_update && nbr && nbr->ei && old_version != nbr->tlv_version &&
        nbr->state == EIGRP_NEIGHBOR_UP) {
        eigrp_intf_encoder_peer_remove(nbr->ei, old_version);
        eigrp_intf_encoder_peer_add(nbr->ei, nbr->tlv_version);
    }
}

void __wrap_eigrp_nbr_codec_update(eigrp_instance_t *eigrp)
{
    srl_in_codec_update = true;
    __real_eigrp_nbr_codec_update(eigrp);
    srl_in_codec_update = false;
}

static eigrp_route_descriptor_t *srl_test_mock_route = NULL;

static eigrp_route_descriptor_t *srl_test_mock_decoder(
    eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
    eigrp_stream_t *pkt, uint16_t pktlen)
{
    (void)eigrp;
    (void)nbr;
    (void)pktlen;
    if (pkt)
        pkt->getp = pkt->endp;
    eigrp_route_descriptor_t *r = srl_test_mock_route;
    srl_test_mock_route = NULL;
    return r;
}

int srlTestRel030OverridesCheck(void)
{
    eigrp_instance_t eigrp;
    eigrp_intf_t ei;
    eigrp_nbr_t nbr1, nbr2;

    memset(&eigrp, 0, sizeof(eigrp));
    memset(&ei, 0, sizeof(ei));
    memset(&nbr1, 0, sizeof(nbr1));
    memset(&nbr2, 0, sizeof(nbr2));

    eigrp.topology_table = eigrp_topology_table_create();
    eigrp.topology_changes = eigrp_list_create();
    eigrp.eiflist = eigrp_list_create();
    if (!eigrp.topology_table || !eigrp.topology_changes || !eigrp.eiflist)
        return -1;
    eigrp.af_vectors.classic_internal_tlv_type = EIGRP_TLV_IPv4_INT;
    eigrp.af_vectors.classic_external_tlv_type = EIGRP_TLV_IPv4_EXT;
    eigrp.max_hops = 100;
    eigrp.k_values[0] = 1;
    eigrp.k_values[2] = 1;
    eigrp.metric_version = EIGRP_TLV_32B_VERSION;

    ei.eigrp = &eigrp;
    ei.params.bandwidth = 100000;
    ei.params.delay = 10;
    ei.nbrs = eigrp_list_create();
    nbr1.ei = &ei;
    nbr2.ei = &ei;

    /* 1. Create a query-retained PASSIVE prefix with two query-retained routes (nbr1 and nbr2). */
    eigrp_prefix_descriptor_t *p1 = eigrp_topology_prefix_create();
    p1->destination.address.afi = EIGRP_AFI_IPV4;
    p1->destination.address.bytes[0] = 10;
    p1->destination.address.bytes[1] = 99;
    p1->destination.address.bytes[2] = 1;
    p1->destination.prefix_length = 24;
    p1->state = EIGRP_FSM_STATE_PASSIVE;
    p1->distance = EIGRP_MAX_METRIC;
    p1->fdistance = EIGRP_MAX_METRIC;
    p1->reported_metric.delay = EIGRP_MAX_METRIC;

    eigrp_route_descriptor_t *r1 = eigrp_topology_route_create(&ei);
    r1->adv_router = &nbr1;
    r1->prefix = p1;
    r1->dest = p1->destination;
    r1->type = EIGRP_TLV_IPv4_INT;
    r1->metric.bandwidth = eigrp_bandwidth_to_scaled(100000);
    r1->metric.delay = eigrp_delay_to_scaled(10);
    r1->reported_metric = r1->metric;
    r1->reported_distance = eigrp_metric_calculate(&eigrp, r1->reported_metric);
    r1->distance = eigrp_metric_total_calculate(&eigrp, r1);
    eigrp_topology_route_insert(&eigrp, p1, r1, true);

    eigrp_route_descriptor_t *r2 = eigrp_topology_route_create(&ei);
    r2->adv_router = &nbr2;
    r2->prefix = p1;
    r2->dest = p1->destination;
    r2->type = EIGRP_TLV_IPv4_INT;
    r2->metric.bandwidth = eigrp_bandwidth_to_scaled(100000);
    r2->metric.delay = eigrp_delay_to_scaled(20);
    r2->reported_metric = r2->metric;
    r2->reported_distance = eigrp_metric_calculate(&eigrp, r2->reported_metric);
    r2->distance = eigrp_metric_total_calculate(&eigrp, r2);
    eigrp_topology_route_insert(&eigrp, p1, r2, true);

    eigrp_prefix_descriptor_add(eigrp.topology_table, p1);

    /* Query-retained PASSIVE prefix must not be counted as an active reachable prefix. */
    if (srl_active_topology_prefix_count(&eigrp) != 0)
        return -2;

    /* 2. Unreachable UPDATE from nbr2 on query-retained p1 must be dropped without promoting r1. */
    eigrp_route_descriptor_t *unreach = eigrp_topology_route_create(&ei);
    unreach->dest = p1->destination;
    unreach->type = EIGRP_TLV_IPv4_INT;
    unreach->metric.delay = EIGRP_MAX_METRIC;
    srl_saved_update_decoder = srl_test_mock_decoder;
    srl_test_mock_route = unreach;
    eigrp_stream_t dummy_pkt = {.getp = 0, .endp = 1, .size = 1};
    if (srl_update_tlv_decoder_intercept(&eigrp, &nbr2, &dummy_pkt, 1) != NULL)
        return -3;
    if (eigrp_prefix_descriptor_lookup(p1, &nbr2) != NULL)
        return -4;
    if (eigrp_prefix_descriptor_lookup(p1, &nbr1) != r1)
        return -5;
    if (p1->distance != EIGRP_MAX_METRIC)
        return -6;

    /* 3. Reachable UPDATE from nbr2 on query-retained p1 must prune nbr1's un-elected QUERY route r1. */
    eigrp_route_descriptor_t *reach = eigrp_topology_route_create(&ei);
    reach->dest = p1->destination;
    reach->type = EIGRP_TLV_IPv4_INT;
    reach->metric.bandwidth = eigrp_bandwidth_to_scaled(100000);
    reach->metric.delay = eigrp_delay_to_scaled(50);
    srl_test_mock_route = reach;
    dummy_pkt.getp = 0;
    if (srl_update_tlv_decoder_intercept(&eigrp, &nbr2, &dummy_pkt, 1) != reach)
        return -7;
    if (eigrp_prefix_descriptor_lookup(p1, &nbr1) != NULL)
        return -8;
    eigrp_topology_route_free(reach);

    /* 4. Poisoned QUERY from nbr1 on query-retained prefix must delete nbr1's retained RDB. */
    eigrp_route_descriptor_t *r1_new = eigrp_topology_route_create(&ei);
    r1_new->adv_router = &nbr1;
    r1_new->prefix = p1;
    r1_new->dest = p1->destination;
    r1_new->type = EIGRP_TLV_IPv4_INT;
    r1_new->metric.bandwidth = eigrp_bandwidth_to_scaled(100000);
    r1_new->metric.delay = eigrp_delay_to_scaled(10);
    r1_new->reported_metric = r1_new->metric;
    r1_new->reported_distance = eigrp_metric_calculate(&eigrp, r1_new->reported_metric);
    r1_new->distance = eigrp_metric_total_calculate(&eigrp, r1_new);
    eigrp_topology_route_insert(&eigrp, p1, r1_new, true);

    eigrp_route_descriptor_t *poison_q = eigrp_topology_route_create(&ei);
    poison_q->dest = p1->destination;
    poison_q->type = EIGRP_TLV_IPv4_INT;
    poison_q->metric.delay = EIGRP_MAX_METRIC;
    srl_saved_query_decoder = srl_test_mock_decoder;
    srl_test_mock_route = poison_q;
    dummy_pkt.getp = 0;
    if (srl_query_tlv_decoder_intercept(&eigrp, &nbr1, &dummy_pkt, 1) != poison_q)
        return -9;
    if (eigrp_prefix_descriptor_lookup(p1, &nbr1) != NULL)
        return -10;
    eigrp_topology_route_free(poison_q);

    /* 5. Peer codec downgrade on UP neighbor must update interface encoder peer counts. */
    {
        eigrp.tlv1_codec.encoder = (void *)1;
        eigrp.tlv1_codec.decoder = (void *)1;
        eigrp.tlv2_codec.encoder = (void *)2;
        eigrp.tlv2_codec.decoder = (void *)2;
        nbr1.state = EIGRP_NEIGHBOR_UP;
        nbr1.tlv_version = EIGRP_TLV_64B_VERSION;
        ei.tlv2_peer_count = 1;
        ei.tlv1_peer_count = 0;
        __wrap_eigrp_nbr_codec_select(&nbr1, EIGRP_TLV_32B_VERSION);
        if (ei.tlv2_peer_count != 0 || ei.tlv1_peer_count != 1)
            return -11;
    }

    /* 6. ACTIVE withdrawing prefix with poisoned successor and unselected non-FS route must not count. */
    eigrp_prefix_descriptor_t *p2 = eigrp_topology_prefix_create();
    p2->destination.address.afi = EIGRP_AFI_IPV4;
    p2->destination.address.bytes[0] = 10;
    p2->destination.address.bytes[1] = 99;
    p2->destination.address.bytes[2] = 2;
    p2->destination.prefix_length = 24;
    p2->state = EIGRP_FSM_STATE_ACTIVE_3;
    p2->distance = 28160;
    p2->fdistance = 28160;

    eigrp_route_descriptor_t *p2_succ = eigrp_topology_route_create(&ei);
    p2_succ->adv_router = &nbr1;
    p2_succ->prefix = p2;
    p2_succ->dest = p2->destination;
    p2_succ->type = EIGRP_TLV_IPv4_INT;
    p2_succ->flags = EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG;
    p2_succ->metric.delay = EIGRP_MAX_METRIC;
    p2_succ->distance = EIGRP_MAX_METRIC;
    eigrp_topology_route_insert(&eigrp, p2, p2_succ, true);

    eigrp_route_descriptor_t *p2_nonfs = eigrp_topology_route_create(&ei);
    p2_nonfs->adv_router = &nbr2;
    p2_nonfs->prefix = p2;
    p2_nonfs->dest = p2->destination;
    p2_nonfs->type = EIGRP_TLV_IPv4_INT;
    p2_nonfs->flags = 0;
    p2_nonfs->metric.bandwidth = eigrp_bandwidth_to_scaled(100000);
    p2_nonfs->metric.delay = eigrp_delay_to_scaled(50);
    p2_nonfs->distance = eigrp_metric_total_calculate(&eigrp, p2_nonfs);
    eigrp_topology_route_insert(&eigrp, p2, p2_nonfs, true);
    eigrp_prefix_descriptor_add(eigrp.topology_table, p2);

    if (srl_active_topology_prefix_count(&eigrp) != 0)
        return -12;

    /* 7. Maximum-prefix admission admits while p2 is withdrawing, and rejects cleanly without AF teardown when full. */
    eigrp_af_config_t af_cfg;
    memset(&af_cfg, 0, sizeof(af_cfg));
    af_cfg.runtime = &eigrp;
    af_cfg.topology_maximum_prefix_configured = true;
    af_cfg.topology_maximum_prefix.maximum = 1;
    af_cfg.topology_maximum_prefix.threshold = 75;
    af_cfg.topology_maximum_prefix.warning_only = false;
    bool created_vr_list = false;
    if (!eigrp_process.virt_router) {
        eigrp_process.virt_router = eigrp_list_create();
        created_vr_list = true;
    }
    (void)eigrp_named_config_create("srl-test-ovr");
    eigrp_named_config_t *parent_cfg = eigrp_named_config_read("srl-test-ovr");
    if (!parent_cfg) {
        if (created_vr_list)
            eigrp_list_delete(&eigrp_process.virt_router);
        return -13;
    }
    parent_cfg->address_families = &af_cfg;

    int rc = 0;
    if (!__wrap_eigrp_topology_prefix_admit(&eigrp, &p2->destination))
        rc = -14;
    else {
        p2->state = EIGRP_FSM_STATE_PASSIVE;
        p2_nonfs->flags = EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG;
        if (srl_active_topology_prefix_count(&eigrp) != 1)
            rc = -15;
        else if (__wrap_eigrp_topology_prefix_admit(&eigrp, &p1->destination))
            rc = -16;
        else if (eigrp.eigrp_pfxlimits_af_state != 0)
            rc = -17;
    }
    parent_cfg->address_families = NULL;
    (void)eigrp_named_config_delete("srl-test-ovr");
    if (created_vr_list)
        eigrp_list_delete(&eigrp_process.virt_router);
    if (rc != 0)
        return rc;

    if (eigrp_topology_table_lookup(eigrp.topology_table, &p2->destination))
        eigrp_prefix_descriptor_delete(&eigrp, eigrp.topology_table, p2);
    if (eigrp_topology_table_lookup(eigrp.topology_table, &p1->destination))
        eigrp_prefix_descriptor_delete(&eigrp, eigrp.topology_table, p1);
    eigrp_list_delete(&ei.nbrs);
    eigrp_list_delete(&eigrp.eiflist);
    eigrp_list_delete(&eigrp.topology_changes);
    eigrp_table_free(eigrp.topology_table);
    srl_saved_update_decoder = NULL;
    srl_saved_query_decoder = NULL;
    return 0;
}
