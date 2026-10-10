package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
	"github.com/rs/zerolog/log"
)

func (d *EigrpDaemon) OnRouteAdd(netinst string, prefix string, nexthop string, metric uint32, wideMetric uint64, isExt bool) {
	if netinst == "" {
		netinst = "default"
	}
	ctx := context.Background()
	parts := strings.Split(prefix, "/")
	if len(parts) != 2 {
		return
	}
	pfxNetIP := net.ParseIP(parts[0])
	if pfxNetIP == nil {
		return
	}
	var pfxIP []byte
	if p4 := pfxNetIP.To4(); p4 != nil {
		pfxIP = p4
	} else if p16 := pfxNetIP.To16(); p16 != nil {
		pfxIP = p16
	} else {
		return
	}
	pfxLen, err := strconv.Atoi(parts[1])
	if err != nil {
		return
	}

	rawNhs := strings.Split(nexthop, ",")
	validNexthops := make([]*ndk.NextHop, 0, len(rawNhs))
	validNhStrs := make([]string, 0, len(rawNhs))

	for _, nh := range rawNhs {
		nh = strings.TrimSpace(nh)
		nhNetIP := net.ParseIP(nh)
		if nhNetIP == nil || nhNetIP.IsUnspecified() || nh == "0.0.0.0" || nh == "::" || nh == "" {
			continue
		}
		var nhIP []byte
		if nh4 := nhNetIP.To4(); nh4 != nil {
			nhIP = nh4
		} else if nh16 := nhNetIP.To16(); nh16 != nil {
			nhIP = nh16
		} else {
			continue
		}
		validNexthops = append(validNexthops, &ndk.NextHop{
			Type:      ndk.NextHop_RESOLUTION_TYPE_REGULAR,
			ResolveTo: ndk.NextHop_RESOLVE_TO_TYPE_DIRECT,
			Nexthop: &ndk.NextHop_IpNexthop{
				IpNexthop: &ndk.IpAddressPb{IpAddress: nhIP},
			},
		})
		validNhStrs = append(validNhStrs, nh)
	}

	if len(validNexthops) == 0 {
		log.Debug().Str("netinst", netinst).Str("prefix", prefix).Str("nexthops", nexthop).Msg("Ignoring route with unspecified or invalid nexthop")
		return
	}

	sanitizedPfx := strings.ReplaceAll(strings.ReplaceAll(prefix, ".", "_"), "/", "_")
	sanitizedPfx = strings.ReplaceAll(sanitizedPfx, ":", "_")
	nhgName := fmt.Sprintf("eigrp_nhg_%s_%s_sdk", netinst, sanitizedPfx)

	nhgReq := &ndk.NextHopGroupRequest{
		GroupInfos: []*ndk.NextHopGroupInfo{
			{
				Key: &ndk.NextHopGroupKey{
					Name:                nhgName,
					NetworkInstanceName: netinst,
				},
				Data: &ndk.NextHopGroup{
					Nexthops: validNexthops,
				},
			},
		},
	}
	if _, err := d.nhgClient.NextHopGroupAddOrUpdate(ctx, nhgReq); err != nil {
		log.Error().Err(err).Str("netinst", netinst).Str("nhg", nhgName).Msg("NextHopGroupAddOrUpdate failed")
		return
	}

	pref := uint32(90) // EIGRP Internal
	if isExt {
		pref = 170     // EIGRP External
	}

	routeReq := &ndk.RouteAddRequest{
		Routes: []*ndk.RouteInfo{
			{
				Key: &ndk.RouteKey{
					NetworkInstanceName: netinst,
					IpPrefix: &ndk.IpAddrPrefLenPb{
						IpAddr:       &ndk.IpAddressPb{IpAddress: pfxIP},
						PrefixLength: uint32(pfxLen),
					},
				},
				Data: &ndk.Route{
					NexthopGroupName: nhgName,
					Preference:       pref,
					Metric:           metric,
				},
			},
		},
	}
	if _, err := d.routeClient.RouteAddOrUpdate(ctx, routeReq); err != nil {
		log.Error().Err(err).Str("netinst", netinst).Str("prefix", prefix).Msg("RouteAddOrUpdate failed")
		return
	}

	primaryNh := validNhStrs[0]
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	inst.routes[prefix] = &RouteInfo{
		Prefix:     prefix,
		NextHop:    primaryNh,
		Metric:     metric,
		WideMetric: wideMetric,
		External:   isExt,
	}
	d.mu.Unlock()
	log.Info().Str("netinst", netinst).Str("prefix", prefix).Strs("nexthops", validNhStrs).Uint32("pref", pref).Uint64("wide_metric", wideMetric).Msg("Injected EIGRP route into FIB")
	go d.publishTelemetry(context.Background())
}

func (d *EigrpDaemon) WithdrawAfRoutes(netinst, afName string) {
	if netinst == "" {
		netinst = "default"
	}
	inst := d.GetInstance(netinst)
	if inst == nil {
		return
	}
	d.mu.Lock()
	var toWithdraw []string
	for pfx := range inst.routes {
		isV6 := strings.Contains(pfx, ":")
		if (afName == "ipv6-unicast" && isV6) || (afName == "ipv4-unicast" && !isV6) {
			toWithdraw = append(toWithdraw, pfx)
			delete(inst.routes, pfx)
		}
	}
	d.mu.Unlock()

	for _, pfx := range toWithdraw {
		d.withdrawRouteInternal(netinst, pfx)
	}
	if len(toWithdraw) > 0 {
		go d.publishTelemetry(context.Background())
	}
}

func (d *EigrpDaemon) withdrawRouteInternal(netinst string, prefix string) {
	ctx := context.Background()
	parts := strings.Split(prefix, "/")
	if len(parts) != 2 {
		return
	}
	pfxNetIP := net.ParseIP(parts[0])
	if pfxNetIP == nil {
		return
	}
	var pfxIP []byte
	if p4 := pfxNetIP.To4(); p4 != nil {
		pfxIP = p4
	} else if p16 := pfxNetIP.To16(); p16 != nil {
		pfxIP = p16
	} else {
		return
	}
	pfxLen, err := strconv.Atoi(parts[1])
	if err != nil {
		return
	}

	sanitizedPfx := strings.ReplaceAll(strings.ReplaceAll(prefix, ".", "_"), "/", "_")
	sanitizedPfx = strings.ReplaceAll(sanitizedPfx, ":", "_")
	nhgName := fmt.Sprintf("eigrp_nhg_%s_%s_sdk", netinst, sanitizedPfx)

	delReq := &ndk.RouteDeleteRequest{
		Routes: []*ndk.RouteKey{
			{
				NetworkInstanceName: netinst,
				IpPrefix: &ndk.IpAddrPrefLenPb{
					IpAddr:       &ndk.IpAddressPb{IpAddress: pfxIP},
					PrefixLength: uint32(pfxLen),
				},
			},
		},
	}
	if _, err := d.routeClient.RouteDelete(ctx, delReq); err != nil {
		log.Error().Err(err).Str("netinst", netinst).Str("prefix", prefix).Msg("RouteDelete failed")
	}
	nhgDelReq := &ndk.NextHopGroupDeleteRequest{
		GroupKeys: []*ndk.NextHopGroupKey{
			{
				Name:                nhgName,
				NetworkInstanceName: netinst,
			},
		},
	}
	if _, err := d.nhgClient.NextHopGroupDelete(ctx, nhgDelReq); err != nil {
		log.Debug().Err(err).Str("netinst", netinst).Str("nhg", nhgName).Msg("NextHopGroupDelete failed")
	}

	log.Info().Str("netinst", netinst).Str("prefix", prefix).Msg("Withdrew EIGRP route from FIB")
}

func (d *EigrpDaemon) OnRouteDel(netinst string, prefix string) {
	if netinst == "" {
		netinst = "default"
	}

	inst := d.GetInstance(netinst)
	if inst != nil {
		d.mu.RLock()
		isPreserved := inst.restarting && inst.gracefulRestart != nil && inst.gracefulRestart.AdminState == "enable"
		d.mu.RUnlock()
		if isPreserved {
			log.Info().Str("netinst", netinst).Str("prefix", prefix).Msg("Graceful restart active: preserving FIB forwarding route during restart")
			return
		}
	}

	if inst == nil {
		inst = d.GetInstance(netinst)
	}
	if inst != nil {
		d.mu.Lock()
		delete(inst.routes, prefix)
		d.mu.Unlock()
	}

	d.withdrawRouteInternal(netinst, prefix)
	go d.publishTelemetry(context.Background())
}
