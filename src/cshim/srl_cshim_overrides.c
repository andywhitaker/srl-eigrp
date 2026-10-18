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
        if (!pfx)
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
    if (existing) {
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

bool __wrap_eigrp_nbr_prefix_admit(eigrp_instance_t *runtime, eigrp_nbr_t *neighbor,
                                   const eigrp_prefix_t *prefix)
{
    if (!__real_eigrp_nbr_prefix_admit(runtime, neighbor, prefix))
        return false;
    if (runtime && prefix && eigrp_topology_table_lookup(runtime->topology_table, prefix))
        return __wrap_eigrp_topology_prefix_admit(runtime, prefix);
    return true;
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
    __real_eigrp_update_receive(eigrp, nbr, eigrph, pkt, ei, length);
    if (nbr && (nbr->state == EIGRP_NEIGHBOR_PENDING || nbr->state == EIGRP_NEIGHBOR_UP) && !nbr->t_holddown) {
        eigrp_nbr_holddown_update(nbr);
    }
}
