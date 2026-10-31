package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
	"github.com/rs/zerolog/log"
)

func computeNhgName(netinst string, nhStrs []string) string {
	sortedNhs := make([]string, len(nhStrs))
	copy(sortedNhs, nhStrs)
	sort.Strings(sortedNhs)
	h := sha256.New()
	for _, nh := range sortedNhs {
		h.Write([]byte(nh))
		h.Write([]byte{0})
	}
	hash := fmt.Sprintf("%x", h.Sum(nil))[:16]
	return fmt.Sprintf("eigrp_nhg_%s_%s_sdk", netinst, hash)
}

func (d *EigrpDaemon) OnRouteAdd(netinst string, prefix string, nexthop string, metric uint32, wideMetric uint64, isExt bool, preference uint32, ifname ...string) {
	if netinst == "" {
		netinst = "default"
	}
	if wideMetric == ^uint64(0) || wideMetric >= 0xffffffffffff || wideMetric == 0xffffffff || metric == 0xFFFFFFFF {
		d.OnRouteDel(netinst, prefix)
		return
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

	var rawIfnames []string
	if len(ifname) > 0 && ifname[0] != "" {
		rawIfnames = strings.Split(ifname[0], ",")
	}

	rawNhs := strings.Split(nexthop, ",")
	validNexthops := make([]*ndk.NextHop, 0, len(rawNhs))
	validNhStrs := make([]string, 0, len(rawNhs))
	validRawNhs := make([]string, 0, len(rawNhs))
	var primaryIf string

	for i, nh := range rawNhs {
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
		var nhIf string
		if i < len(rawIfnames) {
			nhIf = normalizeIfName(strings.TrimSpace(rawIfnames[i]))
		}
		if primaryIf == "" && nhIf != "" {
			primaryIf = nhIf
		}

		validNexthops = append(validNexthops, &ndk.NextHop{
			Type:      ndk.NextHop_RESOLUTION_TYPE_REGULAR,
			ResolveTo: ndk.NextHop_RESOLVE_TO_TYPE_DIRECT,
			Nexthop: &ndk.NextHop_IpNexthop{
				IpNexthop: &ndk.IpAddressPb{IpAddress: nhIP},
			},
		})

		nhStr := nhNetIP.String()
		nhDisplay := nhStr
		if nhNetIP.IsLinkLocalUnicast() && nhIf != "" {
			nhDisplay = fmt.Sprintf("%s%%%s", nhStr, nhIf)
		}
		validNhStrs = append(validNhStrs, nhDisplay)
		validRawNhs = append(validRawNhs, nhStr)
	}

	if len(validNexthops) == 0 {
		log.Debug().Str("netinst", netinst).Str("prefix", prefix).Str("nexthops", nexthop).Msg("Ignoring route with unspecified or invalid nexthop")
		return
	}

	afiName := "ipv4-unicast"
	if strings.Contains(prefix, ":") {
		afiName = "ipv6-unicast"
	}

	primaryNh := validRawNhs[0]
	var rawIfStr string
	if len(ifname) > 0 {
		rawIfStr = ifname[0]
	}

	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	pref := preference
	if pref == 0 || (!isExt && pref == 90) || (isExt && pref == 170) {
		if isExt {
			pref = uint32(inst.GetAfiExternalPreference(afiName))
		} else {
			pref = uint32(inst.GetAfiPreference(afiName))
		}
	}
	if inst.learnedRoutes == nil {
		inst.learnedRoutes = make(map[string]*RouteInfo)
	}
	inst.learnedRoutes[prefix] = &RouteInfo{
		Prefix:                prefix,
		NextHop:               primaryNh,
		Interface:             primaryIf,
		RawNextHop:            nexthop,
		RawInterface:          rawIfStr,
		Metric:                metric,
		WideMetric:            wideMetric,
		External:              isExt,
		Preference:            uint8(pref),
		RefreshedAfterRestart: inst.restarting,
	}
	impPolicyName := inst.GetAfiImportPolicy(afiName)
	d.mu.Unlock()

	if impPolicyName != "" {
		pol, _ := d.getPolicyDef(impPolicyName)
		if pol != nil {
			cand := CandidateRoute{
				Prefix:     prefix,
				RouteType:  "eigrp",
				RouteOwner: "srl_eigrpd",
				NextHop:    primaryNh,
				AFI:        afiName,
			}
			accepted, _ := evaluateRoutePolicyWithDefault(cand, pol, nil)
			if !accepted {
				d.mu.Lock()
				_, wasInstalled := inst.routes[prefix]
				delete(inst.routes, prefix)
				d.mu.Unlock()
				if wasInstalled {
					d.withdrawRouteInternal(netinst, prefix)
				}
				d.triggerDebouncedTelemetry()
				return
			}
		}
	}

	nhgName := computeNhgName(netinst, validNhStrs)
	pfxKey := netinst + ":" + prefix

	d.nhgMu.Lock()
	if d.prefixToNhg == nil {
		d.prefixToNhg = make(map[string]string)
	}
	if d.nhgRefCounts == nil {
		d.nhgRefCounts = make(map[string]int)
	}
	needNhgAdd := (d.nhgRefCounts[nhgName] == 0)
	oldNhg := d.prefixToNhg[pfxKey]
	var needOldNhgDel bool
	if oldNhg != nhgName {
		d.prefixToNhg[pfxKey] = nhgName
		d.nhgRefCounts[nhgName]++
		if oldNhg != "" {
			d.nhgRefCounts[oldNhg]--
			if d.nhgRefCounts[oldNhg] <= 0 {
				delete(d.nhgRefCounts, oldNhg)
				needOldNhgDel = true
			}
		}
	}
	d.nhgMu.Unlock()

	if needNhgAdd {
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
		if d.nhgClient != nil {
			if _, err := d.nhgClient.NextHopGroupAddOrUpdate(ctx, nhgReq); err != nil {
				log.Error().Err(err).Str("netinst", netinst).Str("nhg", nhgName).Msg("NextHopGroupAddOrUpdate failed")
				return
			}
		}
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
	if d.routeClient != nil {
		if _, err := d.routeClient.RouteAddOrUpdate(ctx, routeReq); err != nil {
			log.Error().Err(err).Str("netinst", netinst).Str("prefix", prefix).Msg("RouteAddOrUpdate failed")
			return
		}
	}

	if needOldNhgDel && oldNhg != "" {
		nhgDelReq := &ndk.NextHopGroupDeleteRequest{
			GroupKeys: []*ndk.NextHopGroupKey{
				{
					Name:                oldNhg,
					NetworkInstanceName: netinst,
				},
			},
		}
		if d.nhgClient != nil {
			if _, err := d.nhgClient.NextHopGroupDelete(ctx, nhgDelReq); err != nil {
				log.Debug().Err(err).Str("netinst", netinst).Str("nhg", oldNhg).Msg("NextHopGroupDelete failed for superseded NHG")
			}
		}
	}

	d.mu.Lock()
	inst.routes[prefix] = &RouteInfo{
		Prefix:                prefix,
		NextHop:               primaryNh,
		Interface:             primaryIf,
		RawNextHop:            nexthop,
		RawInterface:          rawIfStr,
		Metric:                metric,
		WideMetric:            wideMetric,
		External:              isExt,
		Preference:            uint8(pref),
		RefreshedAfterRestart: inst.restarting,
	}
	d.mu.Unlock()
	d.mu.RLock()
	syncActive := d.fibSyncActive
	d.mu.RUnlock()
	if syncActive {
		d.ScheduleFibSyncEnd(3 * time.Second)
	}

	d.triggerDebouncedTelemetry()
}

func (d *EigrpDaemon) reconcileImportedRoutes(netinst string) {
	if netinst == "all" {
		d.mu.RLock()
		netinsts := make([]string, 0, len(d.instances))
		for ni := range d.instances {
			netinsts = append(netinsts, ni)
		}
		d.mu.RUnlock()
		for _, ni := range netinsts {
			d.reconcileImportedRoutes(ni)
		}
		return
	}
	if netinst == "" {
		netinst = "default"
	}
	inst := d.GetInstance(netinst)
	if inst == nil {
		return
	}
	d.mu.RLock()
	learned := make([]*RouteInfo, 0, len(inst.learnedRoutes))
	for _, r := range inst.learnedRoutes {
		if r != nil {
			cp := *r
			learned = append(learned, &cp)
		}
	}
	d.mu.RUnlock()

	for _, r := range learned {
		nh := r.RawNextHop
		if nh == "" {
			nh = r.NextHop
		}
		if r.RawInterface != "" {
			d.OnRouteAdd(netinst, r.Prefix, nh, r.Metric, r.WideMetric, r.External, 0, r.RawInterface)
		} else if r.Interface != "" {
			d.OnRouteAdd(netinst, r.Prefix, nh, r.Metric, r.WideMetric, r.External, 0, r.Interface)
		} else {
			d.OnRouteAdd(netinst, r.Prefix, nh, r.Metric, r.WideMetric, r.External, 0)
		}
	}
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
	for pfx := range inst.learnedRoutes {
		isV6 := strings.Contains(pfx, ":")
		if (afName == "ipv6-unicast" && isV6) || (afName == "ipv4-unicast" && !isV6) {
			delete(inst.learnedRoutes, pfx)
		}
	}
	for pfx := range inst.topology {
		isV6 := strings.Contains(pfx, ":")
		if (afName == "ipv6-unicast" && isV6) || (afName == "ipv4-unicast" && !isV6) {
			delete(inst.topology, pfx)
		}
	}
	for pfx := range inst.tempTopology {
		isV6 := strings.Contains(pfx, ":")
		if (afName == "ipv6-unicast" && isV6) || (afName == "ipv4-unicast" && !isV6) {
			delete(inst.tempTopology, pfx)
		}
	}
	for ip := range inst.neighbors {
		isV6 := strings.Contains(ip, ":")
		if (afName == "ipv6-unicast" && isV6) || (afName == "ipv4-unicast" && !isV6) {
			delete(inst.neighbors, ip)
		}
	}
	for ip := range inst.tempNeighbors {
		isV6 := strings.Contains(ip, ":")
		if (afName == "ipv6-unicast" && isV6) || (afName == "ipv4-unicast" && !isV6) {
			delete(inst.tempNeighbors, ip)
		}
	}
	d.mu.Unlock()

	for _, pfx := range toWithdraw {
		d.withdrawRouteInternal(netinst, pfx)
	}
	d.triggerDebouncedTelemetry()
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
	if d.routeClient != nil {
		if _, err := d.routeClient.RouteDelete(ctx, delReq); err != nil {
			log.Error().Err(err).Str("netinst", netinst).Str("prefix", prefix).Msg("RouteDelete failed")
		}
	}

	pfxKey := netinst + ":" + prefix
	d.nhgMu.Lock()
	var nhgToDelete string
	if d.prefixToNhg != nil {
		if nhgName, ok := d.prefixToNhg[pfxKey]; ok {
			delete(d.prefixToNhg, pfxKey)
			if d.nhgRefCounts != nil {
				d.nhgRefCounts[nhgName]--
				if d.nhgRefCounts[nhgName] <= 0 {
					delete(d.nhgRefCounts, nhgName)
					nhgToDelete = nhgName
				}
			}
		}
	}
	d.nhgMu.Unlock()

	if nhgToDelete != "" && d.nhgClient != nil {
		nhgDelReq := &ndk.NextHopGroupDeleteRequest{
			GroupKeys: []*ndk.NextHopGroupKey{
				{
					Name:                nhgToDelete,
					NetworkInstanceName: netinst,
				},
			},
		}
		if _, err := d.nhgClient.NextHopGroupDelete(ctx, nhgDelReq); err != nil {
			log.Debug().Err(err).Str("netinst", netinst).Str("nhg", nhgToDelete).Msg("NextHopGroupDelete failed")
		}
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
		existingRoute := inst.routes[prefix]
		alreadyRefreshed := existingRoute != nil && existingRoute.RefreshedAfterRestart
		isPreserved := inst.restarting && !alreadyRefreshed && inst.gracefulRestart != nil && inst.gracefulRestart.AdminState == "enable"
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
		delete(inst.learnedRoutes, prefix)
		d.mu.Unlock()
	}

	d.withdrawRouteInternal(netinst, prefix)
	d.triggerDebouncedTelemetry()
}

var (
	fibSyncMu    sync.Mutex
	fibSyncTimer *time.Timer

	ribTeleMu    sync.Mutex
	ribTeleTimer *time.Timer
)

func (d *EigrpDaemon) triggerDebouncedTelemetry() {
	ribTeleMu.Lock()
	defer ribTeleMu.Unlock()

	if ribTeleTimer != nil {
		ribTeleTimer.Stop()
	}
	ribTeleTimer = time.AfterFunc(300*time.Millisecond, func() {
		d.publishTelemetry(context.Background())
	})
}

func (d *EigrpDaemon) FibSyncStart(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	d.fibSyncActive = true
	d.mu.Unlock()

	log.Info().Msg("Initiating NDK hitless FIB state synchronization")
	if d.nhgClient != nil {
		if _, err := d.nhgClient.SyncStart(ctx, &ndk.SyncRequest{}); err != nil {
			log.Error().Err(err).Msg("nhgClient.SyncStart failed")
		}
	}
	if d.routeClient != nil {
		if _, err := d.routeClient.SyncStart(ctx, &ndk.SyncRequest{}); err != nil {
			log.Error().Err(err).Msg("routeClient.SyncStart failed")
		}
	}
}

func (d *EigrpDaemon) FibSyncEnd(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	if !d.fibSyncActive {
		d.mu.Unlock()
		return
	}
	d.fibSyncActive = false
	d.mu.Unlock()

	fibSyncMu.Lock()
	if fibSyncTimer != nil {
		fibSyncTimer.Stop()
		fibSyncTimer = nil
	}
	fibSyncMu.Unlock()

	log.Info().Msg("Completing NDK hitless FIB state synchronization (purging orphaned routes and NHGs)")
	if d.routeClient != nil {
		if _, err := d.routeClient.SyncEnd(ctx, &ndk.SyncRequest{}); err != nil {
			log.Error().Err(err).Msg("routeClient.SyncEnd failed")
		}
	}
	if d.nhgClient != nil {
		if _, err := d.nhgClient.SyncEnd(ctx, &ndk.SyncRequest{}); err != nil {
			log.Error().Err(err).Msg("nhgClient.SyncEnd failed")
		}
	}
}

func (d *EigrpDaemon) ScheduleFibSyncEnd(delay time.Duration) {
	d.mu.RLock()
	active := d.fibSyncActive
	d.mu.RUnlock()
	if !active {
		return
	}

	fibSyncMu.Lock()
	defer fibSyncMu.Unlock()

	if fibSyncTimer != nil {
		fibSyncTimer.Stop()
	}
	fibSyncTimer = time.AfterFunc(delay, func() {
		d.FibSyncEnd(context.Background())
	})
}
