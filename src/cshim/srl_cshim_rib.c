#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "srl_cshim.h"

void eigrp_rib_init(void) {}
void eigrp_rib_finish(void) {}
void eigrp_rib_instance_delete(eigrp_instance_t *eigrp) {
    (void)eigrp;
}

eigrp_result_t eigrp_rib_redistribute_add(eigrp_instance_t *e, const eigrp_redist_source_t *s) {
    (void)e;
    (void)s;
    return EIGRP_RESULT_SUCCESS;
}

eigrp_result_t eigrp_rib_redistribute_remove(eigrp_instance_t *e, const eigrp_redist_source_t *s) {
    (void)e;
    (void)s;
    return EIGRP_RESULT_SUCCESS;
}

eigrp_result_t eigrp_rib_route_add(eigrp_instance_t *eigrp, const eigrp_rib_route_t *route) {
    if (!eigrp || !route) return EIGRP_RESULT_INVALID_ARGUMENT;

    char pfx_str[128];
    char addr_str[64];
    int pfx_afi = (route->prefix.address.afi == EIGRP_AFI_IPV6) ? AF_INET6 : AF_INET;
    if (!inet_ntop(pfx_afi, route->prefix.address.bytes, addr_str, sizeof(addr_str))) {
        return EIGRP_RESULT_INVALID_ARGUMENT;
    }
    if (pfx_afi == AF_INET6) {
        struct in6_addr pfx_in6;
        if (inet_pton(AF_INET6, addr_str, &pfx_in6) == 1 && IN6_IS_ADDR_LINKLOCAL(&pfx_in6)) {
            return EIGRP_RESULT_SUCCESS;
        }
    }
    snprintf(pfx_str, sizeof(pfx_str), "%s/%u", addr_str, route->prefix.prefix_length);

    char nhs_buf[512] = "";
    const char *netinst = srl_netinst_by_instance(eigrp);

    for (size_t i = 0; i < route->nexthop_count; i++) {
        if (!route->nexthops[i].gateway_present) continue;
        char single_nh[64] = "";
        int nh_afi = (route->nexthops[i].gateway.afi == EIGRP_AFI_IPV6) ? AF_INET6 : AF_INET;
        if (inet_ntop(nh_afi, route->nexthops[i].gateway.bytes, single_nh, sizeof(single_nh))) {
            if (pfx_afi == AF_INET6) {
                srl_resolve_v6_gateway(netinst, route->nexthops[i].ifindex, single_nh, sizeof(single_nh));
            }
            if (single_nh[0] != '\0') {
                if (nhs_buf[0] != '\0') {
                    strncat(nhs_buf, ",", sizeof(nhs_buf) - strlen(nhs_buf) - 1);
                }
                strncat(nhs_buf, single_nh, sizeof(nhs_buf) - strlen(nhs_buf) - 1);
            }
        }
    }
    if (nhs_buf[0] == '\0') {
        if (pfx_afi == AF_INET6) {
            strncpy(nhs_buf, "::", sizeof(nhs_buf));
        } else {
            strncpy(nhs_buf, "0.0.0.0", sizeof(nhs_buf));
        }
    }
    int is_ext = (route->install.type == EIGRP_RIB_ROUTE_EXTERNAL) ? 1 : 0;
    uint32_t pref = route->install.admin_dist;
    if (pref == 0) {
        pref = is_ext ? 170 : 90;
    }
    uint8_t rib_scale = srl_get_rib_scale(netinst);
    if (rib_scale == 0) rib_scale = 128;
    bool is_unreachable = (route->metric >= EIGRP_64BIT_METRIC_INFINITY ||
                           route->metric >= 0xffffffffffffULL ||
                           route->metric == 4294967295ULL);
    bool is_local = srl_is_local_prefix(netinst, &route->prefix);

    if (is_unreachable || (route->nexthop_count == 0 && !is_local)) {
        srlGoRouteDel((char *)netinst, pfx_str);
        return EIGRP_RESULT_SUCCESS;
    }
    uint64_t scaled = route->metric / rib_scale;
    if (scaled == 0 && route->metric > 0) scaled = 1;
    if (scaled > 4294967294ULL) scaled = 4294967294ULL;
    uint32_t rib_metric = (uint32_t)scaled;
    srlGoRouteAdd((char *)netinst, pfx_str, nhs_buf, rib_metric, (uint64_t)route->metric, is_ext, pref);
    return EIGRP_RESULT_SUCCESS;
}

eigrp_result_t eigrp_rib_route_del(eigrp_instance_t *eigrp, const eigrp_prefix_t *prefix) {
    if (!eigrp || !prefix) return EIGRP_RESULT_INVALID_ARGUMENT;

    char pfx_str[128];
    char addr_str[64];
    int pfx_afi = (prefix->address.afi == EIGRP_AFI_IPV6) ? AF_INET6 : AF_INET;
    if (!inet_ntop(pfx_afi, prefix->address.bytes, addr_str, sizeof(addr_str))) {
        return EIGRP_RESULT_INVALID_ARGUMENT;
    }
    if (pfx_afi == AF_INET6) {
        struct in6_addr pfx_in6;
        if (inet_pton(AF_INET6, addr_str, &pfx_in6) == 1 && IN6_IS_ADDR_LINKLOCAL(&pfx_in6)) {
            return EIGRP_RESULT_SUCCESS;
        }
    }
    snprintf(pfx_str, sizeof(pfx_str), "%s/%u", addr_str, prefix->prefix_length);

    const char *netinst = srl_netinst_by_instance(eigrp);
    srlGoRouteDel((char *)netinst, pfx_str);
    return EIGRP_RESULT_SUCCESS;
}
