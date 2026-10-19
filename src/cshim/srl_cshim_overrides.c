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
#include "eigrp_summary.h"
#include "eigrp_neighbor.h"
#include "eigrp_eventlog.h"
#include "eigrp_log.h"
#include "eigrp.h"

static void srl_topology_route_queue_resort(eigrp_list_t *routes)
{
    eigrp_list_item_t *a, *b;
    bool changed;

    if (!routes)
        return;
    do {
        changed = false;
        for (a = routes->head; a && a->next; a = a->next) {
            b = a->next;
            if (((eigrp_route_descriptor_t *)a->data)->distance
                <= ((eigrp_route_descriptor_t *)b->data)->distance)
                continue;
            void *tmp = a->data;
            a->data = b->data;
            b->data = tmp;
            changed = true;
        }
    } while (changed);
}

void __wrap_eigrp_topology_metric_update(eigrp_instance_t *eigrp)
{
    eigrp_table_node_t *rn;
    eigrp_prefix_descriptor_t *prefix;
    eigrp_route_descriptor_t *route, *best;
    eigrp_topology_route_iterator_t iterator;

    if (!eigrp || !eigrp->topology_table)
        return;
    for (rn = eigrp_table_first(eigrp->topology_table); rn;
         rn = eigrp_table_next(rn)) {
        prefix = rn->info;
        if (!prefix || prefix->state != EIGRP_FSM_STATE_PASSIVE)
            continue;
        bool query_retained_only = (prefix->distance == EIGRP_MAX_METRIC
                                    && prefix->fdistance == EIGRP_MAX_METRIC
                                    && prefix->reported_metric.delay == EIGRP_MAX_METRIC);
        for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
             route = eigrp_topology_route_iterator_next(&iterator)) {
            if (route->adv_router == eigrp->neighbor_self) {
                route->reported_distance = 0;
                if (route->metric.delay == EIGRP_MAX_METRIC) {
                    route->distance = EIGRP_MAX_METRIC;
                } else if (route->ei && route->type == eigrp->af_vectors.classic_internal_tlv_type) {
                    eigrp_metrics_t m;
                    memset(&m, 0, sizeof(m));
                    m.bandwidth = eigrp_bandwidth_to_scaled(route->ei->params.bandwidth);
                    m.delay = eigrp_delay_to_scaled(route->ei->params.delay);
                    m.load = route->ei->params.load;
                    m.reliability = route->ei->params.reliability;
                    m.mtu[0] = 0xDC;
                    m.mtu[1] = 0x05;
                    m.mtu[2] = 0x00;
                    m.hop_count = 0;
                    route->metric = m;
                    route->reported_metric = m;
                    route->total_metric = m;
                    route->distance = eigrp_metric_calculate(eigrp, m);
                } else if (!route->ei && route->type == eigrp->af_vectors.classic_external_tlv_type) {
                    eigrp_metrics_t scaled_m = route->metric;
                    scaled_m.delay = eigrp_delay_to_scaled(route->metric.delay);
                    route->distance = eigrp_metric_calculate(eigrp, scaled_m);
                } else {
                    route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
                }
            } else {
                route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
                if (route->ei)
                    route->distance = eigrp_metric_total_calculate(eigrp, route);
                else
                    route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
            }
        }
        srl_topology_route_queue_resort(prefix->internal_routes);
        srl_topology_route_queue_resort(prefix->external_routes);
        if (query_retained_only)
            continue;
        best = eigrp_topology_route_read(prefix);
        if (best) {
            prefix->distance = best->distance;
            prefix->fdistance = best->distance;
            prefix->rdistance = best->distance;
            prefix->reported_metric = best->total_metric;
        }
        eigrp_topology_update_node_flags(eigrp, prefix);
        eigrp_update_routing_table(eigrp, prefix);
        prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
        if (!eigrp_list_lookup(eigrp->topology_changes, prefix))
            eigrp_list_add(eigrp->topology_changes, prefix);
    }
    eigrp_update_send_all(eigrp, NULL);
}

extern bool __real_eigrp_summary_route_build(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
                                             const eigrp_prefix_descriptor_t *prefix,
                                             const eigrp_route_descriptor_t *route,
                                             eigrp_prefix_descriptor_t *summary_prefix,
                                             eigrp_route_descriptor_t *summary_route);

extern bool __real_eigrp_summary_query_route_build(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
                                                   const eigrp_prefix_t *destination,
                                                   eigrp_prefix_descriptor_t *summary_prefix,
                                                   eigrp_route_descriptor_t *summary_route);

struct eigrp_summary_metric_entry {
    eigrp_prefix_t prefix;
    eigrp_summary_metric_config_t config;
    struct eigrp_summary_metric_entry *next;
};

struct eigrp_summary_state {
    bool auto_summary;
    struct eigrp_summary_metric_entry *metrics;
};

static const eigrp_summary_metric_config_t *srl_summary_metric_lookup(
    eigrp_instance_t *eigrp, const eigrp_prefix_t *prefix)
{
    eigrp_af_config_t *af = eigrp_af_config_runtime_read(eigrp);
    struct eigrp_summary_metric_entry *entry;

    if (!af || !af->summary_state || !prefix)
        return NULL;
    for (entry = af->summary_state->metrics; entry; entry = entry->next) {
        if (entry->prefix.address.afi == prefix->address.afi
            && entry->prefix.prefix_length == prefix->prefix_length
            && memcmp(entry->prefix.address.bytes, prefix->address.bytes,
                      sizeof(entry->prefix.address.bytes)) == 0)
            return &entry->config;
    }
    return NULL;
}

static void srl_fixup_summary_route(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
                                    eigrp_prefix_descriptor_t *summary_prefix,
                                    eigrp_route_descriptor_t *summary_route)
{
    if (!eigrp || !summary_prefix || !summary_route)
        return;

    eigrp_route_descriptor_t *best_route = NULL;
    uint32_t selected_distance = EIGRP_MAX_METRIC;

    if (eigrp->topology_table) {
        eigrp_table_node_t *rn;
        for (rn = eigrp_table_first(eigrp->topology_table); rn;
             rn = eigrp_table_next(rn)) {
            eigrp_prefix_descriptor_t *candidate = rn->info;
            eigrp_route_descriptor_t *candidate_route;
            if (!candidate
                || candidate->destination.address.afi != summary_prefix->destination.address.afi
                || candidate->destination.prefix_length <= summary_prefix->destination.prefix_length
                || !eigrp_prefix_address_match(&summary_prefix->destination,
                                               &candidate->destination.address))
                continue;
            candidate_route = eigrp_topology_route_read(candidate);
            if (!candidate_route || candidate->distance == EIGRP_MAX_METRIC
                || candidate_route->metric.delay == EIGRP_MAX_METRIC)
                continue;
            /* Do not summarize a route learned from a neighbor on ei back out ei */
            if (ei && candidate_route->ei == ei && candidate_route->adv_router != eigrp->neighbor_self)
                continue;
            /* Prefer components not on the outgoing interface when distances tie */
            if (!best_route || candidate->distance < selected_distance
                || (ei && best_route->ei == ei && candidate_route->ei != ei
                    && candidate->distance == selected_distance)) {
                best_route = candidate_route;
                selected_distance = candidate->distance;
            }
        }
    }

    summary_route->ei = NULL;
    summary_route->adv_router = eigrp->neighbor_self;
    summary_route->type = eigrp->af_vectors.classic_internal_tlv_type;
    memset(&summary_route->nexthop, 0, sizeof(summary_route->nexthop));
    summary_route->prefix = summary_prefix;
    summary_route->dest = summary_prefix->destination;

    if (best_route && selected_distance != EIGRP_MAX_METRIC) {
        const eigrp_summary_metric_config_t *metric_config =
            srl_summary_metric_lookup(eigrp, &summary_prefix->destination);
        summary_route->metric = best_route->total_metric;
        summary_route->reported_metric = summary_route->metric;
        summary_route->total_metric = summary_route->metric;
        summary_route->distance = selected_distance;
        summary_route->reported_distance = 0;
        if (metric_config && metric_config->metric_configured) {
            eigrp_metric_values_convert(&metric_config->metric, &summary_route->metric);
            summary_route->reported_metric = summary_route->metric;
            summary_route->total_metric = summary_route->metric;
        }
        summary_prefix->reported_metric = summary_route->metric;
        summary_prefix->distance = selected_distance;
        summary_prefix->fdistance = selected_distance;
    } else {
        summary_route->metric.delay = EIGRP_MAX_METRIC;
        summary_route->reported_metric.delay = EIGRP_MAX_METRIC;
        summary_route->total_metric.delay = EIGRP_MAX_METRIC;
        summary_route->distance = EIGRP_MAX_METRIC;
        summary_prefix->reported_metric.delay = EIGRP_MAX_METRIC;
    }
}

bool __wrap_eigrp_summary_route_build(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
                                      const eigrp_prefix_descriptor_t *prefix,
                                      const eigrp_route_descriptor_t *route,
                                      eigrp_prefix_descriptor_t *summary_prefix,
                                      eigrp_route_descriptor_t *summary_route)
{
    if (!__real_eigrp_summary_route_build(eigrp, ei, prefix, route, summary_prefix, summary_route))
        return false;
    srl_fixup_summary_route(eigrp, ei, summary_prefix, summary_route);
    return true;
}

bool __wrap_eigrp_summary_query_route_build(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
                                            const eigrp_prefix_t *destination,
                                            eigrp_prefix_descriptor_t *summary_prefix,
                                            eigrp_route_descriptor_t *summary_route)
{
    if (__real_eigrp_summary_query_route_build(eigrp, ei, destination, summary_prefix, summary_route)) {
        srl_fixup_summary_route(eigrp, ei, summary_prefix, summary_route);
        return true;
    }
    if (!eigrp || !ei || !destination || !summary_prefix || !summary_route)
        return false;
    /* If the queried destination is a specific prefix covered by a summary on ei
     * and not leaked, answer the QUERY with unreachable so the neighbor does not
     * re-install the suppressed specific route. */
    if (eigrp_summary_covers(eigrp, ei, destination)
        && !eigrp_summary_specific_leak(eigrp, ei, destination)) {
        if (ei->address.address.afi == destination->address.afi
            && ei->address.prefix_length == destination->prefix_length
            && eigrp_prefix_address_match(&ei->address, &destination->address))
            return false;
        memset(summary_prefix, 0, sizeof(*summary_prefix));
        summary_prefix->destination = *destination;
        summary_prefix->state = EIGRP_FSM_STATE_PASSIVE;
        summary_prefix->reported_metric.delay = EIGRP_MAX_METRIC;
        memset(summary_route, 0, sizeof(*summary_route));
        summary_route->prefix = summary_prefix;
        summary_route->dest = *destination;
        summary_route->type = eigrp->af_vectors.classic_internal_tlv_type;
        summary_route->metric.delay = EIGRP_MAX_METRIC;
        summary_route->reported_metric.delay = EIGRP_MAX_METRIC;
        summary_route->total_metric.delay = EIGRP_MAX_METRIC;
        summary_route->distance = EIGRP_MAX_METRIC;
        return true;
    }
    return false;
}

extern bool __real_eigrp_nbr_prefix_admit(eigrp_instance_t *runtime, eigrp_nbr_t *neighbor,
                                          const eigrp_prefix_t *prefix);

static uint32_t srl_active_topology_prefix_count(eigrp_instance_t *runtime)
{
    eigrp_table_node_t *node;
    uint32_t count = 0;

    if (!runtime || !runtime->topology_table)
        return 0;
    for (node = eigrp_table_first(runtime->topology_table); node;
         node = eigrp_table_next(node)) {
        eigrp_prefix_descriptor_t *pfx = node->info;
        if (!pfx || pfx->distance == EIGRP_MAX_METRIC)
            continue;
        eigrp_route_descriptor_t *best = eigrp_topology_route_read(pfx);
        if (best && best->distance != EIGRP_MAX_METRIC && best->metric.delay != EIGRP_MAX_METRIC)
            count++;
    }
    return count;
}

bool __wrap_eigrp_topology_prefix_admit(eigrp_instance_t *runtime,
                                        const eigrp_prefix_t *prefix)
{
    eigrp_af_config_t *af;
    const eigrp_prefix_limit_t *limit;
    eigrp_prefix_descriptor_t *existing;

    if (!runtime || !prefix)
        return false;
    existing = eigrp_topology_table_lookup(runtime->topology_table, prefix);
    if (existing && existing->distance != EIGRP_MAX_METRIC) {
        eigrp_route_descriptor_t *best = eigrp_topology_route_read(existing);
        if (best && best->distance != EIGRP_MAX_METRIC && best->metric.delay != EIGRP_MAX_METRIC)
            return true;
    }
    af = eigrp_af_config_runtime_read(runtime);
    if (!af || !af->topology_maximum_prefix_configured)
        return true;
    limit = &af->topology_maximum_prefix;
    uint32_t count = srl_active_topology_prefix_count(runtime);
    if (eigrp_prefix_limit_threshold_crossed(limit, count))
        eigrp_log(EIGRP_LOG_WARNING,
                  "EIGRP topology maximum-prefix threshold reached (%u/%u)",
                  count + 1U, limit->maximum);
    if (!eigrp_prefix_limit_allows(limit, count, false)) {
        (void)eigrp_eventlog_msg_add(runtime, EIGRP_EVENTLOG_OPCODE_PREFIX_LIMIT_REJECT,
                                     prefix, EIGRP_EVENTLOG_PREFIX_LIMIT_TOPOLOGY,
                                     count + 1U, limit->maximum, 0);
        return false;
    }
    return true;
}

static _Thread_local eigrp_packet_decoder_t srl_saved_update_decoder = NULL;
static _Thread_local bool srl_in_unreachable_update = false;

static bool srl_prefix_is_query_retained_passive(const eigrp_prefix_descriptor_t *prefix)
{
    return prefix
           && prefix->state == EIGRP_FSM_STATE_PASSIVE
           && prefix->distance == EIGRP_MAX_METRIC
           && prefix->fdistance == EIGRP_MAX_METRIC
           && prefix->reported_metric.delay == EIGRP_MAX_METRIC;
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

bool __wrap_eigrp_nbr_prefix_admit(eigrp_instance_t *runtime, eigrp_nbr_t *neighbor,
                                   const eigrp_prefix_t *prefix)
{
    if (srl_in_unreachable_update)
        return true;
    if (!__real_eigrp_nbr_prefix_admit(runtime, neighbor, prefix))
        return false;
    if (runtime && prefix && eigrp_topology_table_lookup(runtime->topology_table, prefix))
        return __wrap_eigrp_topology_prefix_admit(runtime, prefix);
    return true;
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

    if (topology_route) {
        if (!__wrap_eigrp_nbr_prefix_admit(eigrp, nbr, &route->dest)) {
            if (srl_prefix_is_query_retained_passive(prefix)) {
                eigrp_route_descriptor_delete(eigrp, prefix, topology_route);
                eigrp_update_topology_table_prefix(eigrp, eigrp->topology_table, prefix);
            }
            eigrp_topology_route_free(route);
            return NULL;
        }
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
    if (nbr && eigrph) {
        uint32_t flags = ntohl(eigrph->flags);
        uint32_t seq = ntohl(eigrph->sequence);
        if (!(flags & EIGRP_INIT_FLAG) && seq != 0 && nbr->peer_init_sequence_number != 0) {
            nbr->peer_init_sequence_number = UINT32_MAX;
        }
    }
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
    if (nbr && (nbr->state == EIGRP_NEIGHBOR_PENDING || nbr->state == EIGRP_NEIGHBOR_UP) && !nbr->t_holddown) {
        eigrp_nbr_holddown_update(nbr);
    }
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

    if (eigrp && eigrp->topology_table && nbr) {
        eigrp_table_node_t *rn;
        for (rn = eigrp_table_first(eigrp->topology_table); rn; rn = eigrp_table_next(rn)) {
            eigrp_prefix_descriptor_t *pe = rn->info;
            if (!pe)
                continue;
            eigrp_route_descriptor_t *route = eigrp_prefix_descriptor_lookup(pe, nbr);
            if (route)
                route->adv_router = NULL;
        }
    }
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
    eigrp_list_insert(p1->internal_routes, r1);

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
    eigrp_list_insert(p1->internal_routes, r2);

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

    /* 4. Retained poisoned route after neighbor-down must have adv_router detached to NULL. */
    eigrp_route_descriptor_t *r_poison = eigrp_topology_route_create(&ei);
    r_poison->adv_router = &nbr1;
    r_poison->prefix = p1;
    r_poison->dest = p1->destination;
    r_poison->type = EIGRP_TLV_IPv4_INT;
    r_poison->metric.delay = EIGRP_MAX_METRIC;
    r_poison->reported_metric.delay = EIGRP_MAX_METRIC;
    r_poison->reported_distance = EIGRP_MAX_METRIC;
    r_poison->distance = EIGRP_MAX_METRIC;
    p1->distance = 281600;
    p1->fdistance = 281600;
    p1->reported_metric.delay = eigrp_delay_to_scaled(10);
    p1->req_action |= EIGRP_FSM_NEED_UPDATE;
    eigrp_list_insert(p1->internal_routes, r_poison);

    __wrap_eigrp_topology_neighbor_down(&eigrp, &nbr1);
    if (r_poison->adv_router != NULL)
        return -9;

    eigrp_route_descriptor_delete(&eigrp, p1, r_poison);
    eigrp_prefix_descriptor_delete(&eigrp, eigrp.topology_table, p1);
    eigrp_list_delete(&ei.nbrs);
    eigrp_list_delete(&eigrp.eiflist);
    eigrp_list_delete(&eigrp.topology_changes);
    eigrp_table_free(eigrp.topology_table);
    srl_saved_update_decoder = NULL;
    return 0;
}
