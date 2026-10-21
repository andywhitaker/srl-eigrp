#ifndef SRL_CSHIM_H_
#define SRL_CSHIM_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "eigrp.h"
#include "eigrp_cli.h"
#include "eigrp_mgnt.h"
#include "eigrp_metric.h"
#include "eigrp_rib.h"
#include "eigrp_sys.h"

eigrp_result_t eigrp_topology_redistributed_route_update(
	eigrp_instance_t *eigrp, const eigrp_rib_route_t *source_route,
	const eigrp_metrics_t *metric);

#ifdef __cplusplus
extern "C" {
#endif

// Bridge functions exported from Go
extern void srlGoRouteAdd(char *netinst, char *prefix, char *nexthop, uint32_t metric, uint64_t wide_metric, int is_external, uint32_t preference, char *ifname);
const char *srl_get_ifname_by_index(const char *netinst, eigrp_ifindex_t ifidx);
extern void srlGoRouteDel(char *netinst, char *prefix);
extern void srlGoLog(int level, char *msg);
extern void srlGoNeighborReport(char *netinst, char *ip, char *ifname, char *state, uint16_t hold, uint64_t uptime, uint32_t srtt, uint32_t rto, char *bfd_state, char *restart_state, char *auth_mode);
extern void srlGoInterfaceReport(char *netinst, char *ifname, char *ip_addr, uint32_t prefixlen, char *oper_state);
extern void srlGoTopologyPrefixReport(char *netinst, char *prefix, int active, uint32_t fd, uint64_t wide_fd, uint32_t succ_count);
extern void srlGoTopologyRouteReport(char *netinst, char *nexthop, char *ifname, int is_succ, int is_feas_succ, uint32_t dist, uint64_t wide_dist, uint32_t rd, uint64_t wide_rd);
extern void srlGoTrafficReport(char *netinst, char *ifname, uint64_t rmcast, uint64_t umcast, uint64_t rucast, uint64_t uucast, uint64_t rexmits, uint64_t cr);
const char *srl_netinst_by_instance(eigrp_instance_t *e);

// Host Shim APIs called from Go
int srlShimInit(void);
void srlShimFinish(void);
int srlShimInstanceCreate(const char *netinst, uint16_t asn, const char *router_id);
int srlShimInstanceDelete(const char *netinst);
int srlShimNetworkAdd(const char *netinst, const char *prefix);
int srlShimInterfaceAdd(const char *netinst, const char *ifname, const char *ip_addr, uint32_t prefixlen);
int srlShimInterfacesScan(const char *netinst);
void srlShimInterfacesReport(const char *netinst);
void srlShimNeighborsReport(const char *netinst);
int srlShimNeighborClear(const char *netinst, const char *neighbor_ip);
void srlShimTopologyReport(const char *netinst);
void srlShimTrafficReport(const char *netinst);
int srlShimVarianceUpdate(const char *netinst, uint8_t variance);
int srlShimVarianceUpdateAfi(const char *netinst, const char *afi_name, uint8_t variance);
int srlShimMaxPathsUpdate(const char *netinst, uint8_t max_paths);
int srlShimMaxPathsUpdateAfi(const char *netinst, const char *afi_name, uint8_t max_paths);
int srlShimMaxHopsUpdate(const char *netinst, uint8_t max_hops);
int srlShimMaxHopsUpdateAfi(const char *netinst, const char *afi_name, uint8_t max_hops);
int srlShimActiveTimeUpdate(const char *netinst, uint16_t minutes);
int srlShimInterfaceEnable(const char *netinst, const char *ifname, bool passive, uint16_t hello_interval, uint16_t hold_time, bool admin_up, bool split_horizon, bool next_hop_self, uint32_t bandwidth, uint32_t delay);
int srlShimInterfaceDisable(const char *netinst, const char *ifname);
int srlShimMetricsUpdate(const char *netinst, uint8_t k1, uint8_t k2, uint8_t k3, uint8_t k4, uint8_t k5, uint8_t k6, uint8_t rib_scale, bool wide_metrics);
void srl_set_rib_scale(const char *netinst, uint8_t scale);
uint8_t srl_get_rib_scale(const char *netinst);
int srlShimKeychainAdd(const char *name, uint32_t key_id, const char *key_string, const char *algo);
int srlShimKeychainDel(const char *name);
int srlShimInterfaceAuthSet(const char *netinst, const char *ifname, const char *mode, const char *keychain, const char *auth_key);
int srlShimInterfaceAuthClear(const char *netinst, const char *ifname);
int srlShimInterfaceAuthSetAfi(const char *netinst, const char *ifname, const char *afi, const char *mode, const char *keychain, const char *auth_key);
int srlShimInterfaceAuthClearAfi(const char *netinst, const char *ifname, const char *afi);
int srlShimGracefulRestartUpdate(const char *netinst, bool enabled, uint16_t restart_time, bool helper_mode);
int srlShimGracefulShutdown(const char *netinst);
int srlShimRedistributeUpdate(const char *netinst, const char *policy_name, uint32_t bw, uint32_t delay, uint8_t reliability, uint8_t load, uint32_t mtu);
int srlShimInstanceCreateV6(const char *netinst, uint16_t asn, const char *router_id);
int srlShimRouteOriginateV6(const char *netinst, const char *prefix_str, const char *nexthop_str);
int srlShimInterfaceAddV6(const char *netinst, const char *ifname, const char *ip_addr, uint32_t prefixlen);
int srlShimInterfaceEnableV6(const char *netinst, const char *ifname, bool passive, uint16_t hello_interval, uint16_t hold_time, bool admin_up, bool split_horizon, bool next_hop_self, uint32_t bandwidth, uint32_t delay);
int srlShimInterfaceDisableV6(const char *netinst, const char *ifname);
int srlShimInstanceDeleteV6(const char *netinst, uint16_t asn);
int srlShimRouteWithdrawV6(const char *netinst, const char *prefix_str);
int srlShimRouteRedistributeAdd(const char *netinst, const char *prefix_str, const char *proto_str,
                                const char *nexthop_str, uint32_t bw, uint32_t delay,
                                uint8_t reliability, uint8_t load, uint32_t mtu);
int srlShimRouteRedistributeRemove(const char *netinst, const char *prefix_str, const char *proto_str);
int srl_netns_ipv6_socket_open(const char *netinst);
void srl_resolve_v6_gateway(const char *netinst, eigrp_ifindex_t ifidx, char *nh_str, size_t max_len);
int srl_decrypt_password(const char *in, char *out, size_t out_len);
int srl_netns_restore_root(void);
int srlShimStaticNeighborAdd(const char *netinst, const char *ip_str, const char *ifname);
int srlShimStaticNeighborDel(const char *netinst, const char *ip_str, const char *ifname);
int srlShimSummaryAddressAdd(const char *netinst, const char *ifname, const char *prefix_str, uint8_t distance);
int srlShimSummaryAddressDelete(const char *netinst, const char *ifname, const char *prefix_str);
int srlShimDistanceUpdate(const char *netinst, uint8_t internal_dist, uint8_t external_dist);
int srlShimDistanceUpdateAfi(const char *netinst, const char *afi_name, uint8_t internal_dist, uint8_t external_dist);
void srlShimSetPktFdDisabled(bool disabled);
bool srlShimGetPktFdDisabled(void);
uint32_t srlTestPacketHash(int afi, const void *src, const void *dst, const void *payload, size_t len);
bool srlTestDedupCheck(uint8_t rx_src, uint8_t afi, uint32_t hash, uint16_t len, uint16_t ip_id, uint16_t eigrp_csum);
void srlTestDedupReset(void);
eigrp_ifindex_t srlTestResolveInterfaceV4(const char *netinst, uint32_t sll_ifindex, uint16_t vlan_id, const char *src_ip_str, const char *dst_ip_str);
eigrp_ifindex_t srlTestResolveInterfaceV6(const char *netinst, uint32_t sll_ifindex, uint16_t vlan_id, const char *src_ip6_str, const char *dst_ip6_str);
void srlTestRegisterInterface(const char *netinst, const char *ifname, eigrp_ifindex_t ifidx, eigrp_ifindex_t root_ifidx, const char *ip_addr, uint8_t prefixlen, bool is_v6, bool active);
void srlTestRegisterInterfaceWithVlan(const char *netinst, const char *ifname, eigrp_ifindex_t ifidx, eigrp_ifindex_t root_ifidx, uint16_t vlan_id, const char *ip_addr, uint8_t prefixlen, bool is_v6, bool active);
int srlShimInterfaceSetVlanId(const char *netinst, const char *ifname, uint16_t vlan_id);
bool srl_is_local_prefix(const char *netinst, const eigrp_prefix_t *prefix);
bool srlTestMatchRootWireIfname(const char *dev_name, const char *base_name);
bool srlTestIsLocalPrefix(const char *netinst, const char *prefix_str, bool is_v6);
void srlTestClearInterfaces(void);
uint32_t srlTestRunBPFFilter(const uint32_t *ifindexes, size_t num_if, const uint8_t *pkt, size_t pkt_len, uint32_t ifindex);
extern void srlGoEventLogReport(char *netinst, uint32_t event_num, uint64_t timestamp_ms, char *msg);
int srlShimInterfaceBandwidthPercentUpdate(const char *netinst, const char *ifname, const char *afi_name, uint32_t percent);
int srlShimTrafficShareBalancedUpdate(const char *netinst, const char *afi_name, bool balanced);
int srlShimAutoSummaryUpdate(const char *netinst, const char *afi_name, bool enabled);
int srlShimDefaultMetricUpdate(const char *netinst, const char *afi_name, uint32_t bw, uint32_t delay, uint8_t reliability, uint8_t load, uint32_t mtu);
int srlShimMaxPrefixUpdate(const char *netinst, const char *afi_name, uint32_t max_prefixes, uint8_t threshold, bool warning_only);
int srlShimTopologyClear(const char *netinst, const char *prefix_str);
int srlShimEventLogSizeUpdate(const char *netinst, uint32_t size);
int srlShimEventLogClear(const char *netinst);
void srlShimEventLogReport(const char *netinst);
int srlShimStatisticsClear(const char *netinst);
int srlTestRel030OverridesCheck(void);


#ifdef __cplusplus
}
#endif

#endif // SRL_CSHIM_H_
