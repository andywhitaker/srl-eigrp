package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
	"github.com/rs/zerolog/log"
)

var ifRe = regexp.MustCompile(`^e(\d+)-(\d+)(\.\d+)?$`)

func normalizeIfName(ifname string) string {
	if m := ifRe.FindStringSubmatch(ifname); len(m) > 2 {
		sub := ""
		if len(m) > 3 {
			sub = m[3]
		}
		return fmt.Sprintf("ethernet-%s/%s%s", m[1], m[2], sub)
	}
	return ifname
}

func extractNetinstFromJsPath(jsPath string) string {
	const prefix = `.network_instance{.name=="`
	if strings.HasPrefix(jsPath, prefix) {
		rest := jsPath[len(prefix):]
		if idx := strings.Index(rest, `"`); idx >= 0 {
			return rest[:idx]
		}
	}
	return ""
}

func schemaRank(jsPath string) int {
	if strings.Contains(jsPath, ".default-interface.address-family{") {
		return 1
	}
	if strings.Contains(jsPath, ".address-family{") && !strings.Contains(jsPath, ".interface{") && !strings.Contains(jsPath, ".default-interface{") {
		return 2
	}
	if strings.Contains(jsPath, ".interface{") {
		if strings.Contains(jsPath, ".address-family{") {
			if strings.Contains(jsPath, ".summary-address{") {
				return 6
			}
			return 5
		}
		if strings.Contains(jsPath, ".summary-address{") {
			return 4
		}
		return 3
	}
	if strings.Contains(jsPath, ".neighbor{") {
		return 7
	}
	if strings.Contains(jsPath, ".route{") && !strings.Contains(jsPath, ".topology{") {
		return 8
	}
	if strings.Contains(jsPath, ".static-neighbor{") {
		return 9
	}
	if strings.Contains(jsPath, ".topology{") {
		if strings.Contains(jsPath, "}.route{") {
			return 11
		}
		return 10
	}
	if strings.Contains(jsPath, ".traffic{") {
		return 12
	}
	return 0
}

func buildInterfaceData(
	normName string,
	ipAddr string,
	prefixLen uint32,
	rawOperState string,
	ic *InterfaceConfig,
	defIntf *DefaultInterfaceConfig,
	instOperState string,
) map[string]interface{} {
	adminState := "enable"
	if ic != nil && ic.AdminState != "" {
		adminState = ic.AdminState
	} else if defIntf != nil && defIntf.AdminState != "" {
		adminState = defIntf.AdminState
	}

	operState := "down"
	if instOperState != "down" && adminState != "disable" {
		if rawOperState != "" {
			operState = strings.ToLower(rawOperState)
		} else {
			operState = "up"
		}
	}

	data := map[string]interface{}{
		"interface-name": normName,
		"admin-state":    adminState,
		"oper-state":     operState,
	}

	if operState != "up" {
		downReason := "interface admin disabled"
		if adminState == "enable" {
			if instOperState == "down" {
				downReason = "protocol instance down"
			} else if ipAddr == "" {
				downReason = "no IP address configured"
			} else {
				downReason = "link down or inactive"
			}
		}
		data["oper-down-reason"] = downReason
	}

	if ipAddr != "" {
		data["ip-address"] = ipAddr
		data["prefix-length"] = prefixLen
	}

	if ic != nil && ic.Bandwidth != nil && *ic.Bandwidth > 0 {
		data["bandwidth"] = *ic.Bandwidth
	} else if defIntf != nil && defIntf.Bandwidth != nil && *defIntf.Bandwidth > 0 {
		data["bandwidth"] = *defIntf.Bandwidth
	}

	if ic != nil && ic.Delay != nil && *ic.Delay > 0 {
		data["delay"] = *ic.Delay
	} else if defIntf != nil && defIntf.Delay != nil && *defIntf.Delay > 0 {
		data["delay"] = *defIntf.Delay
	}

	return data
}

func publishInterfaceSublists(
	ni string,
	normName string,
	operState string,
	defIntf *DefaultInterfaceConfig,
	ic *InterfaceConfig,
	instAuth *AuthConfig,
	instOperState string,
	instAfs []AddressFamilyConfig,
	nbrList []*NeighborInfo,
	intfInfo *InterfaceInfo,
	currentKeys map[string]struct{},
	states *[]*ndk.TelemetryInfo,
) {
	defAdmin := "enable"
	if defIntf != nil && defIntf.AdminState != "" {
		defAdmin = defIntf.AdminState
	}
	defPassive := false
	if defIntf != nil {
		defPassive = defIntf.Passive
	}

	operStateNorm := strings.ToLower(operState)

	for _, afName := range []string{"ipv4-unicast", "ipv6-unicast"} {
		afIfKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.interface{.interface-name==\"%s\"}.address-family{.name==\"%s\"}", ni, normName, afName)
		currentKeys[afIfKey] = struct{}{}

		topAfAdmin := "enable"
		if len(instAfs) > 0 {
			topAfAdmin = "disable"
			for _, af := range instAfs {
				if af.Name == afName {
					if af.AdminState != "" {
						topAfAdmin = af.AdminState
					} else {
						topAfAdmin = "enable"
					}
					break
				}
			}
		}

		afEnabled := true
		afPassive := defPassive
		if defIntf != nil {
			afPassive = defIntf.IsAfiPassive(afName)
		}
		helloInterval := uint16(5)
		holdTime := uint16(15)
		splitHorizon := true
		nextHopSelf := false
		if ic != nil {
			afEnabled = ic.IsAfiEnabled(afName, defAdmin)
			afPassive = ic.IsAfiPassive(afName, afPassive)
			helloInterval = ic.GetAfiHelloInterval(afName, defIntf)
			holdTime = ic.GetAfiHoldTime(afName, defIntf)
			splitHorizon = ic.GetAfiSplitHorizon(afName, defIntf)
			nextHopSelf = ic.GetAfiNextHopSelf(afName, defIntf)
		} else if defIntf != nil {
			helloInterval = defIntf.GetAfiHelloInterval(afName)
			holdTime = defIntf.GetAfiHoldTime(afName)
			splitHorizon = defIntf.GetAfiSplitHorizon(afName)
			nextHopSelf = defIntf.GetAfiNextHopSelf(afName)
		}

		adminStateStr := "enable"
		if !afEnabled {
			adminStateStr = "disable"
		}

		effectiveOper := "down"
		if instOperState != "down" && topAfAdmin != "disable" && (operStateNorm == "up" || operStateNorm == "") {
			effectiveOper = "up"
		}

		operStateStr := "down"
		if effectiveOper == "up" && afEnabled {
			operStateStr = "up"
		}

		afData := map[string]interface{}{
			"name":           afName,
			"admin-state":    adminStateStr,
			"oper-state":     operStateStr,
			"passive":        afPassive,
			"hello-interval": helloInterval,
			"hold-time":      holdTime,
			"split-horizon":  splitHorizon,
			"next-hop-self":  nextHopSelf,
		}
		if operStateStr != "up" {
			if adminStateStr == "disable" {
				afData["oper-down-reason"] = "address-family admin disabled"
			} else if instOperState == "down" {
				afData["oper-down-reason"] = "protocol instance down"
			} else {
				afData["oper-down-reason"] = "interface down or unnumbered"
			}
		}

		if afName == "ipv4-unicast" {
			if intfInfo != nil && intfInfo.IPAddress != "" && !strings.Contains(intfInfo.IPAddress, ":") {
				afData["ip-address"] = intfInfo.IPAddress
				afData["prefix-length"] = intfInfo.PrefixLen
			}
		} else if afName == "ipv6-unicast" {
			if intfInfo != nil {
				if intfInfo.IP6Address != "" {
					afData["ip-address"] = intfInfo.IP6Address
					afData["prefix-length"] = intfInfo.PrefixLen6
				} else if strings.Contains(intfInfo.IPAddress, ":") {
					afData["ip-address"] = intfInfo.IPAddress
					afData["prefix-length"] = intfInfo.PrefixLen
				}
			}
		}

		// Authentication
		var auth *AuthConfig
		if ic != nil {
			auth = ic.GetAfiAuthentication(afName, defIntf, instAuth)
		} else if defIntf != nil {
			auth = defIntf.GetAfiAuthentication(afName)
			if auth == nil {
				auth = instAuth
			}
		} else {
			auth = instAuth
		}
		authAdmin := "enable"
		authOper := "down"
		authMode := "none"
		var keychain, authKey string
		if auth != nil {
			if auth.AdminState != "" {
				authAdmin = auth.AdminState
			}
			if auth.Mode != "" {
				authMode = auth.Mode
			}
			keychain = auth.Keychain
			authKey = auth.AuthenticationKey
		}
		if authAdmin == "enable" && operStateStr == "up" && authMode != "none" {
			authOper = "up"
		}
		authMap := map[string]interface{}{
			"admin-state": authAdmin,
			"oper-state":  authOper,
			"mode":        authMode,
		}
		if keychain != "" {
			authMap["keychain"] = keychain
		}
		if authKey != "" {
			authMap["authentication-key"] = authKey
		}
		afData["authentication"] = authMap

		// BFD
		var bfd *BfdConfig
		if ic != nil {
			bfd = ic.GetAfiBfd(afName, defIntf)
		} else if defIntf != nil {
			bfd = defIntf.GetAfiBfd(afName)
		}
		bfdAdmin := "disable"
		bfdTx := uint32(1000000)
		bfdRx := uint32(1000000)
		bfdMult := uint8(3)
		if bfd != nil {
			if bfd.AdminState != "" {
				bfdAdmin = bfd.AdminState
			}
			if bfd.DesiredMinimumTxInterval != nil && *bfd.DesiredMinimumTxInterval > 0 {
				bfdTx = *bfd.DesiredMinimumTxInterval
			}
			if bfd.RequiredMinimumReceive != nil && *bfd.RequiredMinimumReceive > 0 {
				bfdRx = *bfd.RequiredMinimumReceive
			}
			if bfd.DetectionMultiplier != nil && *bfd.DetectionMultiplier > 0 {
				bfdMult = *bfd.DetectionMultiplier
			}
		}
		bfdOper := "down"
		if bfdAdmin == "enable" && operStateStr == "up" {
			bfdOper = "up"
		}
		afData["bfd"] = map[string]interface{}{
			"admin-state":                 bfdAdmin,
			"oper-state":                  bfdOper,
			"desired-minimum-tx-interval": bfdTx,
			"required-minimum-receive":    bfdRx,
			"detection-multiplier":        bfdMult,
		}

		// BFD State
		var afBfdSessionState, afBfdRemoteAddr string
		for _, n := range nbrList {
			if normalizeIfName(n.Interface) == normName {
				isNbrV6 := strings.Contains(n.IPAddress, ":")
				if (afName == "ipv6-unicast" && isNbrV6) || (afName == "ipv4-unicast" && !isNbrV6) {
					if n.BfdState != "" && n.BfdState != "disabled" {
						afBfdSessionState = n.BfdState
						afBfdRemoteAddr = n.IPAddress
						break
					}
				}
			}
		}
		if afBfdSessionState != "" {
			afData["bfd-state"] = map[string]interface{}{
				"session-state":  afBfdSessionState,
				"remote-address": afBfdRemoteAddr,
			}
		}

		if b, err := json.Marshal(afData); err == nil {
			*states = append(*states, &ndk.TelemetryInfo{
				Key:  &ndk.TelemetryKey{JsPath: afIfKey},
				Data: &ndk.TelemetryData{JsonContent: string(b)},
			})
			log.Info().Str("key", afIfKey).Str("data", string(b)).Msg("Adding interface AF to telemetry")
		}

		// Summary address under address-family
		if ic != nil {
			saList := ic.GetAfiSummaryAddresses(afName)
			for _, sa := range saList {
				if sa.Prefix == "" {
					continue
				}
				dist := sa.Distance
				if dist == 0 {
					dist = 5
				}
				saAfKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.interface{.interface-name==\"%s\"}.address-family{.name==\"%s\"}.summary-address{.prefix==\"%s\"}", ni, normName, afName, sa.Prefix)
				currentKeys[saAfKey] = struct{}{}
				saOper := "up"
				if operStateStr == "down" || instOperState == "down" {
					saOper = "down"
				}
				saData := map[string]interface{}{
					"prefix":     sa.Prefix,
					"distance":   dist,
					"oper-state": saOper,
				}
				if b, err := json.Marshal(saData); err == nil {
					*states = append(*states, &ndk.TelemetryInfo{
						Key:  &ndk.TelemetryKey{JsPath: saAfKey},
						Data: &ndk.TelemetryData{JsonContent: string(b)},
					})
				}
			}
		}
	}
}

func (d *EigrpDaemon) TelemetryWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.CollectAndPublish(ctx)
		}
	}
}

func (d *EigrpDaemon) publishTelemetry(ctx context.Context) {
	d.mu.RLock()
	type instData struct {
		ni                   string
		asn                  uint16
		routerId             string
		adminState           string
		operState            string
		networks             []string
		variance             uint8
		maximumPaths         uint8
		maximumHops          uint8
		ribScale             uint8
		preference           uint8
		externalPreference   uint8
		wideMetrics          bool
		exportPolicy         string
		importPolicy         string
		gracefulRestart      *GracefulRestartConfig
		timers               *TimersConfig
		metrics              *MetricsConfig
		metricWeights        *MetricsConfig
		authentication       *AuthConfig
		defaultIntf          *DefaultInterfaceConfig
		configuredInterfaces map[string]*InterfaceConfig
		addressFamily        []AddressFamilyConfig
		staticNeighbors      map[string]*StaticNeighborConfig
		nbrList              []*NeighborInfo
		routeList            []*RouteInfo
		intfList             []*InterfaceInfo
		topoList             []*TopologyPrefixInfo
		trafficList          []*TrafficInfo
	}
	allInstData := make([]instData, 0, len(d.instances))
	for ni, inst := range d.instances {
		nbrList := make([]*NeighborInfo, 0, len(inst.neighbors))
		for _, n := range inst.neighbors {
			afiName := "ipv4-unicast"
			if strings.Contains(n.IPAddress, ":") {
				afiName = "ipv6-unicast"
			}
			if !inst.IsAfiEnabled(afiName) {
				continue
			}
			normIf := normalizeIfName(n.Interface)
			var ic *InterfaceConfig
			if c, ok := inst.configuredInterfaces[n.Interface]; ok {
				ic = c
			} else if c, ok := inst.configuredInterfaces[normIf]; ok {
				ic = c
			} else {
				for k, v := range inst.configuredInterfaces {
					if normalizeIfName(k) == normIf {
						ic = v
						break
					}
				}
			}
			if ic == nil {
				continue
			}
			defPassive := false
			if inst.defaultIntf != nil {
				defPassive = inst.defaultIntf.IsAfiPassive(afiName)
			}
			isPassive := ic.IsAfiPassive(afiName, defPassive)
			if !isPassive {
				nbrCopy := *n
				if nbrCopy.AuthMode == "" || nbrCopy.AuthMode == "none" {
					auth := ic.GetAfiAuthentication(afiName, inst.defaultIntf, inst.authentication)
					if auth != nil && auth.Mode != "" && auth.Mode != "none" {
						nbrCopy.AuthMode = auth.Mode
					}
				}
				nbrList = append(nbrList, &nbrCopy)
			}
		}
		routeList := make([]*RouteInfo, 0, len(inst.routes))
		for _, r := range inst.routes {
			afiName := "ipv4-unicast"
			if strings.Contains(r.Prefix, ":") {
				afiName = "ipv6-unicast"
			}
			if !inst.IsAfiEnabled(afiName) {
				continue
			}
			routeList = append(routeList, r)
		}
		intfList := make([]*InterfaceInfo, 0, len(inst.interfaces))
		for _, i := range inst.interfaces {
			normName := normalizeIfName(i.Name)
			var ic *InterfaceConfig
			if c, ok := inst.configuredInterfaces[i.Name]; ok {
				ic = c
			} else if c, ok := inst.configuredInterfaces[normName]; ok {
				ic = c
			} else {
				for k, v := range inst.configuredInterfaces {
					if normalizeIfName(k) == normName {
						ic = v
						break
					}
				}
			}
			if ic == nil {
				continue
			}
			intfList = append(intfList, i)
		}
		topoList := make([]*TopologyPrefixInfo, 0, len(inst.topology))
		for _, t := range inst.topology {
			afiName := "ipv4-unicast"
			if strings.Contains(t.Destination, ":") {
				afiName = "ipv6-unicast"
			}
			if !inst.IsAfiEnabled(afiName) {
				continue
			}
			topoList = append(topoList, t)
		}
		trafficList := make([]*TrafficInfo, 0, len(inst.traffic))
		for _, tf := range inst.traffic {
			normIf := normalizeIfName(tf.Interface)
			var ic *InterfaceConfig
			if c, ok := inst.configuredInterfaces[tf.Interface]; ok {
				ic = c
			} else if c, ok := inst.configuredInterfaces[normIf]; ok {
				ic = c
			} else {
				for k, v := range inst.configuredInterfaces {
					if normalizeIfName(k) == normIf {
						ic = v
						break
					}
				}
			}
			if ic == nil {
				continue
			}
			trafficList = append(trafficList, tf)
		}
		networks := make([]string, len(inst.networks))
		copy(networks, inst.networks)

		adminState := inst.adminState
		if adminState == "" {
			adminState = "enable"
		}
		operState := "up"
		if adminState == "disable" || inst.asn == 0 {
			operState = "down"
		}

		for _, n := range nbrList {
			if n.State != "Up" && n.State != "up" && n.OperDownReason == "" {
				n.OperDownReason = "hold-timer expired or peering down"
			}
		}

		seenIntfsSnapshot := make(map[string]bool)
		for _, i := range intfList {
			norm := normalizeIfName(i.Name)
			seenIntfsSnapshot[norm] = true
			if i.OperState != "up" && i.OperState != "Up" && i.OperDownReason == "" {
				if i.AdminState == "disable" {
					i.OperDownReason = "interface admin disabled"
				} else if operState == "down" {
					i.OperDownReason = "protocol instance down"
				} else if i.IPAddress == "" {
					i.OperDownReason = "no IP address configured"
				} else {
					i.OperDownReason = "link down or inactive"
				}
			}
		}
		for rawIfName, ic := range inst.configuredInterfaces {
			norm := normalizeIfName(rawIfName)
			if seenIntfsSnapshot[norm] {
				continue
			}
			seenIntfsSnapshot[norm] = true
			adminSt := "enable"
			if ic != nil && ic.AdminState != "" {
				adminSt = ic.AdminState
			}
			operSt := "down"
			downReason := "interface admin disabled"
			if adminSt == "enable" {
				if operState == "down" {
					downReason = "protocol instance down"
				} else {
					downReason = "no IP address configured"
				}
			}
			intfList = append(intfList, &InterfaceInfo{
				Name:           rawIfName,
				InterfaceName:  norm,
				AdminState:     adminSt,
				IPAddress:      "",
				PrefixLen:      0,
				OperState:      operSt,
				OperDownReason: downReason,
				BfdState:       "disabled",
				AuthMode:       "none",
				Passive:        ic != nil && ic.Passive != nil && *ic.Passive,
			})
		}

		sort.Slice(nbrList, func(i, j int) bool { return nbrList[i].IPAddress < nbrList[j].IPAddress })
		sort.Slice(routeList, func(i, j int) bool { return routeList[i].Prefix < routeList[j].Prefix })
		sort.Slice(intfList, func(i, j int) bool { return normalizeIfName(intfList[i].Name) < normalizeIfName(intfList[j].Name) })
		sort.Slice(trafficList, func(i, j int) bool {
			return normalizeIfName(trafficList[i].Interface) < normalizeIfName(trafficList[j].Interface)
		})
		sort.Slice(topoList, func(i, j int) bool { return topoList[i].Destination < topoList[j].Destination })

		variance := inst.variance
		if variance == 0 {
			variance = 1
		}
		maxPaths := inst.maximumPaths
		if maxPaths == 0 {
			maxPaths = 4
		}
		maxHops := inst.maximumHops
		if maxHops == 0 {
			maxHops = 100
		}
		ribScale := inst.ribScale
		if ribScale == 0 {
			ribScale = 128
		}
		pref := inst.preference
		if pref == 0 {
			pref = 90
		}
		extPref := inst.externalPreference
		if extPref == 0 {
			extPref = 170
		}

		cfgIntfs := make(map[string]*InterfaceConfig, len(inst.configuredInterfaces))
		for k, v := range inst.configuredInterfaces {
			if v != nil {
				c := *v
				cfgIntfs[k] = &c
			}
		}

		var defIntfCopy *DefaultInterfaceConfig
		if inst.defaultIntf != nil {
			c := *inst.defaultIntf
			defIntfCopy = &c
		} else {
			defIntfCopy = &DefaultInterfaceConfig{
				AdminState:    "enable",
				Passive:       false,
				HelloInterval: 5,
				HoldTime:      15,
			}
		}

		var grCopy *GracefulRestartConfig
		if inst.gracefulRestart != nil {
			c := *inst.gracefulRestart
			grCopy = &c
		} else {
			helper := true
			grCopy = &GracefulRestartConfig{
				AdminState:  "enable",
				RestartTime: 120,
				HelperMode:  &helper,
				OperState:   "up",
			}
		}

		var timersCopy *TimersConfig
		if inst.timers != nil {
			c := *inst.timers
			timersCopy = &c
		}
		var metricsCopy *MetricsConfig
		if inst.metrics != nil {
			c := *inst.metrics
			metricsCopy = &c
		}
		var metricWeightsCopy *MetricsConfig
		if inst.metricWeights != nil {
			c := *inst.metricWeights
			metricWeightsCopy = &c
		}
		var authCopy *AuthConfig
		if inst.authentication != nil {
			c := *inst.authentication
			authCopy = &c
		}
		afList := make([]AddressFamilyConfig, len(inst.addressFamily))
		copy(afList, inst.addressFamily)

		staticNbrs := make(map[string]*StaticNeighborConfig, len(inst.staticNeighbors))
		for k, v := range inst.staticNeighbors {
			if v != nil {
				c := *v
				staticNbrs[k] = &c
			}
		}

		allInstData = append(allInstData, instData{
			ni:                   ni,
			asn:                  inst.asn,
			routerId:             inst.routerId,
			adminState:           adminState,
			operState:            operState,
			networks:             networks,
			variance:             variance,
			maximumPaths:         maxPaths,
			maximumHops:          maxHops,
			ribScale:             ribScale,
			preference:           pref,
			externalPreference:   extPref,
			wideMetrics:          inst.wideMetrics,
			exportPolicy:         inst.exportPolicy,
			importPolicy:         inst.importPolicy,
			gracefulRestart:      grCopy,
			timers:               timersCopy,
			metrics:              metricsCopy,
			metricWeights:        metricWeightsCopy,
			authentication:       authCopy,
			defaultIntf:          defIntfCopy,
			configuredInterfaces: cfgIntfs,
			addressFamily:        afList,
			staticNeighbors:      staticNbrs,
			nbrList:              nbrList,
			routeList:            routeList,
			intfList:             intfList,
			topoList:             topoList,
			trafficList:          trafficList,
		})
	}
	d.mu.RUnlock()

	// 1. Build state file for CLI show plugins
	instancesState := make(map[string]interface{})
	defaultState := make(map[string]interface{})

	for _, item := range allInstData {
		instSnapshot := map[string]interface{}{
			"network-instance":    item.ni,
			"autonomous-system":   item.asn,
			"router-id":           item.routerId,
			"admin-state":         item.adminState,
			"oper-state":          item.operState,
			"variance":            item.variance,
			"maximum-paths":       item.maximumPaths,
			"maximum-hops":        item.maximumHops,
			"rib-scale":           item.ribScale,
			"preference":          item.preference,
			"external-preference": item.externalPreference,
			"wide-metrics":        item.wideMetrics,
			"export-policy":       item.exportPolicy,
			"import-policy":       item.importPolicy,
			"graceful-restart":    item.gracefulRestart,
			"default-interface":   item.defaultIntf,
			"timers":              item.timers,
			"metrics":             item.metrics,
			"networks":            item.networks,
			"static-neighbors":    item.staticNeighbors,
			"static-neighbor":     item.staticNeighbors,
			"interfaces":          item.intfList,
			"interface":           item.intfList,
			"neighbors":           item.nbrList,
			"neighbor":            item.nbrList,
			"routes":              item.routeList,
			"route":               item.routeList,
			"topology":            item.topoList,
			"traffic":             item.trafficList,
		}
		instancesState[item.ni] = instSnapshot
		if item.ni == "default" {
			for k, v := range instSnapshot {
				defaultState[k] = v
			}
		}
	}

	stateSnapshot := make(map[string]interface{})
	for k, v := range defaultState {
		stateSnapshot[k] = v
	}
	stateSnapshot["instances"] = instancesState
	stateSnapshot["updated-at"] = time.Now().Format(time.RFC3339)

	if b, err := json.MarshalIndent(stateSnapshot, "", "  "); err == nil {
		_ = atomicWriteFile("/var/run/srl_eigrp_state.json", b, 0644)
		_ = atomicWriteFile("/tmp/srl_eigrp_state.json", b, 0644)
	}

	// 2. Publish to NDK Telemetry State DB across all network instances
	currentKeys := make(map[string]struct{})
	states := make([]*ndk.TelemetryInfo, 0)

	for _, item := range allInstData {
		ni := item.ni

		// Graceful restart data
		grAdmin := "enable"
		grRestartTime := uint16(120)
		grHelperMode := true
		if item.gracefulRestart != nil {
			if item.gracefulRestart.AdminState != "" {
				grAdmin = item.gracefulRestart.AdminState
			}
			if item.gracefulRestart.RestartTime > 0 {
				grRestartTime = item.gracefulRestart.RestartTime
			}
			if item.gracefulRestart.HelperMode != nil {
				grHelperMode = *item.gracefulRestart.HelperMode
			}
		}
		grOper := "up"
		if item.operState == "down" || grAdmin == "disable" {
			grOper = "down"
		}
		grData := map[string]interface{}{
			"admin-state":  grAdmin,
			"oper-state":   grOper,
			"restart-time": grRestartTime,
			"helper-mode":  grHelperMode,
		}

		// Default interface data
		defIntfAdmin := "enable"
		var defIntfBw *uint32
		var defIntfDelay *uint32
		if item.defaultIntf != nil {
			if item.defaultIntf.AdminState != "" {
				defIntfAdmin = item.defaultIntf.AdminState
			}
			defIntfBw = item.defaultIntf.Bandwidth
			defIntfDelay = item.defaultIntf.Delay
		}
		defOper := "up"
		if item.operState == "down" || defIntfAdmin == "disable" {
			defOper = "down"
		}
		defIntfData := map[string]interface{}{
			"admin-state": defIntfAdmin,
			"oper-state":  defOper,
		}
		if defIntfBw != nil && *defIntfBw > 0 {
			defIntfData["bandwidth"] = *defIntfBw
		}
		if defIntfDelay != nil && *defIntfDelay > 0 {
			defIntfData["delay"] = *defIntfDelay
		}

		// Default interface address families
		for _, afName := range []string{"ipv4-unicast", "ipv6-unicast"} {
			defAfKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.default-interface.address-family{.name==\"%s\"}", ni, afName)
			currentKeys[defAfKey] = struct{}{}
			defAfAdmin := defIntfAdmin
			defAfPass := false
			defAfHello := uint16(5)
			defAfHold := uint16(15)
			defAfSplit := true
			defAfNextHop := false
			if item.defaultIntf != nil {
				if !item.defaultIntf.IsAfiEnabled(afName) {
					defAfAdmin = "disable"
				}
				defAfPass = item.defaultIntf.IsAfiPassive(afName)
				defAfHello = item.defaultIntf.GetAfiHelloInterval(afName)
				defAfHold = item.defaultIntf.GetAfiHoldTime(afName)
				defAfSplit = item.defaultIntf.GetAfiSplitHorizon(afName)
				defAfNextHop = item.defaultIntf.GetAfiNextHopSelf(afName)
			}
			defAfOper := "up"
			if defOper == "down" || defAfAdmin == "disable" {
				defAfOper = "down"
			}
			defAfData := map[string]interface{}{
				"name":           afName,
				"admin-state":    defAfAdmin,
				"oper-state":     defAfOper,
				"passive":        defAfPass,
				"hello-interval": defAfHello,
				"hold-time":      defAfHold,
				"split-horizon":  defAfSplit,
				"next-hop-self":  defAfNextHop,
			}
			if defAfOper != "up" {
				if defAfAdmin == "disable" {
					defAfData["oper-down-reason"] = "address-family admin disabled"
				} else {
					defAfData["oper-down-reason"] = "protocol instance down"
				}
			}

			var afAuth *AuthConfig
			if item.defaultIntf != nil {
				afAuth = item.defaultIntf.GetAfiAuthentication(afName)
			}
			if afAuth == nil {
				afAuth = item.authentication
			}
			authAdmin := "enable"
			authOper := "down"
			authMode := "none"
			var keychain, authKey string
			if afAuth != nil {
				if afAuth.AdminState != "" {
					authAdmin = afAuth.AdminState
				}
				if afAuth.Mode != "" {
					authMode = afAuth.Mode
				}
				keychain = afAuth.Keychain
				authKey = afAuth.AuthenticationKey
			}
			if authAdmin == "enable" && defAfOper == "up" && authMode != "none" {
				authOper = "up"
			}
			authMap := map[string]interface{}{
				"admin-state": authAdmin,
				"oper-state":  authOper,
				"mode":        authMode,
			}
			if keychain != "" {
				authMap["keychain"] = keychain
			}
			if authKey != "" {
				authMap["authentication-key"] = authKey
			}
			defAfData["authentication"] = authMap

			var afBfd *BfdConfig
			if item.defaultIntf != nil {
				afBfd = item.defaultIntf.GetAfiBfd(afName)
			}
			bfdAdmin := "disable"
			bfdTx := uint32(1000000)
			bfdRx := uint32(1000000)
			bfdMult := uint8(3)
			if afBfd != nil {
				if afBfd.AdminState != "" {
					bfdAdmin = afBfd.AdminState
				}
				if afBfd.DesiredMinimumTxInterval != nil && *afBfd.DesiredMinimumTxInterval > 0 {
					bfdTx = *afBfd.DesiredMinimumTxInterval
				}
				if afBfd.RequiredMinimumReceive != nil && *afBfd.RequiredMinimumReceive > 0 {
					bfdRx = *afBfd.RequiredMinimumReceive
				}
				if afBfd.DetectionMultiplier != nil && *afBfd.DetectionMultiplier > 0 {
					bfdMult = *afBfd.DetectionMultiplier
				}
			}
			bfdOper := "down"
			if bfdAdmin == "enable" && defAfOper == "up" {
				bfdOper = "up"
			}
			defAfData["bfd"] = map[string]interface{}{
				"admin-state":                 bfdAdmin,
				"oper-state":                  bfdOper,
				"desired-minimum-tx-interval": bfdTx,
				"required-minimum-receive":    bfdRx,
				"detection-multiplier":        bfdMult,
			}

			if b, err := json.Marshal(defAfData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: defAfKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
			}
		}

		// Timers data
		activeTime := uint16(3)
		if item.timers != nil && item.timers.ActiveTime > 0 {
			activeTime = item.timers.ActiveTime
		}
		timersData := map[string]interface{}{
			"active-time": activeTime,
		}

		// Metrics data
		bw := uint8(1)
		load := uint8(0)
		delay := uint8(1)
		rel := uint8(0)
		mtu := uint8(0)
		extAttr := uint8(0)
		ribScale := item.ribScale
		if ribScale == 0 {
			ribScale = 128
		}
		if item.metrics != nil {
			bw = item.metrics.Bandwidth
			load = item.metrics.Load
			delay = item.metrics.Delay
			rel = item.metrics.Reliability
			mtu = item.metrics.Mtu
			if item.metrics.K1 != nil {
				bw = *item.metrics.K1
			}
			if item.metrics.K2 != nil {
				load = *item.metrics.K2
			}
			if item.metrics.K3 != nil {
				delay = *item.metrics.K3
			}
			if item.metrics.K4 != nil {
				rel = *item.metrics.K4
			}
			if item.metrics.K5 != nil {
				mtu = *item.metrics.K5
			}
			if item.metrics.ExtendedAttributes != nil {
				extAttr = *item.metrics.ExtendedAttributes
			} else if item.metrics.K6 != nil {
				extAttr = *item.metrics.K6
			}
		}
		metricsData := map[string]interface{}{
			"bandwidth":           bw,
			"load":                load,
			"delay":               delay,
			"reliability":         rel,
			"mtu":                 mtu,
			"extended-attributes": extAttr,
		}

		// Top-level delivery node (.network_instance{.name==ni}.protocols.eigrp)
		topKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp", ni)
		currentKeys[topKey] = struct{}{}
		topData := map[string]interface{}{
			"admin-state":         item.adminState,
			"oper-state":          item.operState,
			"variance":            item.variance,
			"maximum-paths":       item.maximumPaths,
			"maximum-hops":        item.maximumHops,
			"rib-scale":           item.ribScale,
			"preference":          item.preference,
			"external-preference": item.externalPreference,
			"wide-metrics":        item.wideMetrics,
			"total-neighbors":     len(item.nbrList),
			"total-routes":        len(item.routeList),
			"total-interfaces":    len(item.intfList),
			"graceful-restart":    grData,
			"default-interface":   defIntfData,
			"timers":              timersData,
			"metrics":             metricsData,
		}
		if item.operState != "up" {
			if item.adminState == "disable" {
				topData["oper-down-reason"] = "protocol admin disabled"
			} else if item.asn == 0 {
				topData["oper-down-reason"] = "autonomous system not configured"
			} else {
				topData["oper-down-reason"] = "instance initializing or inactive"
			}
		}
		if item.asn > 0 {
			topData["autonomous-system"] = item.asn
		}
		if item.routerId != "" && item.routerId != "unspecified" && item.routerId != "0.0.0.0" {
			topData["router-id"] = item.routerId
		}
		if item.exportPolicy != "" {
			topData["export-policy"] = item.exportPolicy
		}
		if item.importPolicy != "" {
			topData["import-policy"] = item.importPolicy
		}
		if item.metricWeights != nil {
			topData["metric-weights"] = map[string]interface{}{
				"bandwidth":   item.metricWeights.Bandwidth,
				"load":        item.metricWeights.Load,
				"delay":       item.metricWeights.Delay,
				"reliability": item.metricWeights.Reliability,
				"mtu":         item.metricWeights.Mtu,
			}
		}
		if item.authentication != nil && item.authentication.Mode != "" {
			authMap := map[string]interface{}{
				"mode": item.authentication.Mode,
			}
			if item.authentication.Keychain != "" {
				authMap["keychain"] = item.authentication.Keychain
			}
			if item.authentication.AuthenticationKey != "" {
				authMap["authentication-key"] = item.authentication.AuthenticationKey
			}
			topData["authentication"] = authMap
		}
		if b, err := json.Marshal(topData); err == nil {
			states = append(states, &ndk.TelemetryInfo{
				Key:  &ndk.TelemetryKey{JsPath: topKey},
				Data: &ndk.TelemetryData{JsonContent: string(b)},
			})
		}

		// Static neighbors
		for _, sn := range item.staticNeighbors {
			if sn.IPAddress == "" {
				continue
			}
			snKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.static-neighbor{.ip-address==\"%s\"}", ni, sn.IPAddress)
			currentKeys[snKey] = struct{}{}
			operState := "down"
			if item.operState != "down" {
				for _, n := range item.nbrList {
					if n.IPAddress == sn.IPAddress && n.State == "Up" {
						operState = "up"
						break
					}
				}
			}
			snData := map[string]interface{}{
				"ip-address": sn.IPAddress,
				"interface":  normalizeIfName(sn.Interface),
				"oper-state": operState,
			}
			if operState != "up" {
				snData["oper-down-reason"] = "neighbor unreachable or inactive"
			}
			if b, err := json.Marshal(snData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: snKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
				log.Info().Str("key", snKey).Str("data", string(b)).Msg("Added static-neighbor to telemetry")
			}
		}

		// Neighbors
		for _, n := range item.nbrList {
			nbrKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.neighbor{.ip-address==\"%s\"}", ni, n.IPAddress)
			currentKeys[nbrKey] = struct{}{}
			bfdSt := n.BfdState
			if bfdSt == "" {
				bfdSt = "none"
			}
			rstSt := n.RestartState
			if rstSt == "" {
				rstSt = "normal"
			}
			afName := "ipv4-unicast"
			if strings.Contains(n.IPAddress, ":") {
				afName = "ipv6-unicast"
			}
			authMd := n.AuthMode
			if authMd == "" || authMd == "none" {
				normIf := normalizeIfName(n.Interface)
				var ic *InterfaceConfig
				if c, ok := item.configuredInterfaces[n.Interface]; ok {
					ic = c
				} else if c, ok := item.configuredInterfaces[normIf]; ok {
					ic = c
				}
				if ic != nil {
					auth := ic.GetAfiAuthentication(afName, item.defaultIntf, item.authentication)
					if auth != nil && auth.Mode != "" && auth.Mode != "none" {
						authMd = auth.Mode
					}
				} else if item.defaultIntf != nil {
					authDef := item.defaultIntf.GetAfiAuthentication(afName)
					if authDef != nil && authDef.Mode != "" && authDef.Mode != "none" {
						authMd = authDef.Mode
					}
				}
			}
			if authMd == "" {
				authMd = "none"
			}
			nbrData := map[string]interface{}{
				"ip-address":     n.IPAddress,
				"address-family": afName,
				"interface":      normalizeIfName(n.Interface),
				"state":          n.State,
				"hold-time":      n.HoldTime,
				"uptime":         fmt.Sprintf("%ds", n.Uptime),
				"srtt-ms":        n.SRTT,
				"rto-ms":         n.RTO,
				"bfd-state":      bfdSt,
				"restart-state":  rstSt,
				"auth-mode":      authMd,
			}
			if n.State != "Up" && n.State != "up" {
				nbrData["oper-down-reason"] = "hold-timer expired or peering down"
			}
			if b, err := json.Marshal(nbrData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: nbrKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
			}
		}

		// Routes
		for _, r := range item.routeList {
			pref := r.Preference
			if pref == 0 {
				if r.External {
					pref = item.externalPreference
				} else {
					pref = item.preference
				}
			}
			routeKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.route{.prefix==\"%s\"}", ni, r.Prefix)
			currentKeys[routeKey] = struct{}{}
			routeData := map[string]interface{}{
				"prefix":      r.Prefix,
				"next-hop":    r.NextHop,
				"metric":      r.Metric,
				"wide-metric": r.WideMetric,
				"rib-scale":   item.ribScale,
				"external":    r.External,
				"preference":  pref,
			}
			if b, err := json.Marshal(routeData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: routeKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
			}
		}

		// Interfaces
		seenIntfs := make(map[string]bool)
		for _, i := range item.intfList {
			normName := normalizeIfName(i.Name)
			seenIntfs[normName] = true
			intfKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.interface{.interface-name==\"%s\"}", ni, normName)
			currentKeys[intfKey] = struct{}{}

			ic := item.configuredInterfaces[normName]
			if ic == nil {
				ic = item.configuredInterfaces[i.Name]
			}

			intfData := buildInterfaceData(
				normName,
				i.IPAddress,
				i.PrefixLen,
				i.OperState,
				ic,
				item.defaultIntf,
				item.operState,
			)

			if b, err := json.Marshal(intfData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: intfKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
				log.Info().Str("key", intfKey).Str("data", string(b)).Msg("Adding interface to telemetry")
			}

			publishInterfaceSublists(
				ni,
				normName,
				i.OperState,
				item.defaultIntf,
				ic,
				item.authentication,
				item.operState,
				item.addressFamily,
				item.nbrList,
				i,
				currentKeys,
				&states,
			)
		}

		// Configured interfaces not currently reported by C engine (e.g. admin disabled)
		for rawIfName, ic := range item.configuredInterfaces {
			normName := normalizeIfName(rawIfName)
			if seenIntfs[normName] {
				continue
			}
			seenIntfs[normName] = true
			intfKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.interface{.interface-name==\"%s\"}", ni, normName)
			currentKeys[intfKey] = struct{}{}

			intfData := buildInterfaceData(
				normName,
				"",
				0,
				"down",
				ic,
				item.defaultIntf,
				item.operState,
			)

			if b, err := json.Marshal(intfData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: intfKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
			}

			publishInterfaceSublists(
				ni,
				normName,
				"down",
				item.defaultIntf,
				ic,
				item.authentication,
				item.operState,
				item.addressFamily,
				item.nbrList,
				nil,
				currentKeys,
				&states,
			)
		}

		// Address family
		for _, afName := range []string{"ipv4-unicast", "ipv6-unicast"} {
			afAdmin := "enable"
			var expPol, impPol string
			foundAf := false
			for _, af := range item.addressFamily {
				if af.Name == afName {
					foundAf = true
					if af.AdminState != "" {
						afAdmin = af.AdminState
					}
					expPol = af.ExportPolicy
					impPol = af.ImportPolicy
					break
				}
			}
			if len(item.addressFamily) > 0 && !foundAf {
				continue
			}
			afKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.address-family{.name==\"%s\"}", ni, afName)
			currentKeys[afKey] = struct{}{}
			afOper := "up"
			if item.operState == "down" || afAdmin == "disable" {
				afOper = "down"
			}
			afPref := item.preference
			afExtPref := item.externalPreference
			for _, af := range item.addressFamily {
				if af.Name == afName {
					if af.Preference > 0 {
						afPref = af.Preference
					}
					if af.ExternalPreference > 0 {
						afExtPref = af.ExternalPreference
					}
					break
				}
			}
			afData := map[string]interface{}{
				"name":                afName,
				"admin-state":         afAdmin,
				"oper-state":          afOper,
				"preference":          afPref,
				"external-preference": afExtPref,
			}
			if afOper != "up" {
				if afAdmin == "disable" {
					afData["oper-down-reason"] = "address-family admin disabled"
				} else {
					afData["oper-down-reason"] = "protocol instance down"
				}
			}
			if expPol != "" {
				afData["export-policy"] = expPol
			}
			if impPol != "" {
				afData["import-policy"] = impPol
			}
			if b, err := json.Marshal(afData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: afKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
			}
		}

		// Traffic
		for _, tf := range item.trafficList {
			normIf := normalizeIfName(tf.Interface)
			trafKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.traffic{.interface==\"%s\"}", ni, normIf)
			currentKeys[trafKey] = struct{}{}
			trafData := map[string]interface{}{
				"interface":            normIf,
				"reliable-multicast":   tf.ReliableMcast,
				"unreliable-multicast": tf.UnreliableMcast,
				"reliable-unicast":     tf.ReliableUcast,
				"unreliable-unicast":   tf.UnreliableUcast,
				"retransmissions":      tf.Retransmissions,
				"cr-packets":           tf.CRPackets,
			}
			if b, err := json.Marshal(trafData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: trafKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
			}
		}

		// Topology
		for _, t := range item.topoList {
			topoKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.topology{.destination==\"%s\"}", ni, t.Destination)
			currentKeys[topoKey] = struct{}{}
			topoData := map[string]interface{}{
				"destination":            t.Destination,
				"active":                 t.Active,
				"feasible-distance":      t.FD,
				"wide-feasible-distance": t.WideFD,
				"successor-count":        t.SuccessorCount,
			}
			if b, err := json.Marshal(topoData); err == nil {
				states = append(states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: topoKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
			}

			for _, r := range t.Routes {
				routeKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.topology{.destination==\"%s\"}.route{.next-hop==\"%s\"}", ni, t.Destination, r.NextHop)
				currentKeys[routeKey] = struct{}{}
				routeData := map[string]interface{}{
					"next-hop":               r.NextHop,
					"interface":              normalizeIfName(r.Interface),
					"successor":              r.Successor,
					"feasible-successor":     r.FeasibleSucc,
					"distance":               r.Distance,
					"wide-distance":          r.WideDistance,
					"reported-distance":      r.ReportedDistance,
					"wide-reported-distance": r.WideRD,
				}
				if b, err := json.Marshal(routeData); err == nil {
					states = append(states, &ndk.TelemetryInfo{
						Key:  &ndk.TelemetryKey{JsPath: routeKey},
						Data: &ndk.TelemetryData{JsonContent: string(b)},
					})
				}
			}
		}
	}

	// Delete removed keys
	d.mu.Lock()
	var delKeys []*ndk.TelemetryKey
	for oldKey := range d.prevTeleKeys {
		if _, exists := currentKeys[oldKey]; !exists {
			delKeys = append(delKeys, &ndk.TelemetryKey{JsPath: oldKey})
		}
	}
	d.prevTeleKeys = currentKeys
	d.mu.Unlock()

	if len(delKeys) > 0 && d.teleClient != nil {
		delReq := &ndk.TelemetryDeleteRequest{Keys: delKeys}
		if _, err := d.teleClient.TelemetryDelete(ctx, delReq); err != nil {
			log.Debug().Err(err).Msg("TelemetryDelete failed")
		}
	}

	// Sort all telemetry states strictly by network-instance and YANG schema definition order
	sort.Slice(states, func(a, b int) bool {
		niA := extractNetinstFromJsPath(states[a].Key.JsPath)
		niB := extractNetinstFromJsPath(states[b].Key.JsPath)
		if niA != niB {
			return niA < niB
		}

		rankA := schemaRank(states[a].Key.JsPath)
		rankB := schemaRank(states[b].Key.JsPath)
		if rankA != rankB {
			return rankA < rankB
		}

		return states[a].Key.JsPath < states[b].Key.JsPath
	})

	// Add or update current states
	if len(states) > 0 && d.teleClient != nil {
		req := &ndk.TelemetryUpdateRequest{States: states}
		resp, err := d.teleClient.TelemetryAddOrUpdate(ctx, req)
		if err != nil {
			log.Warn().Err(err).Msg("TelemetryAddOrUpdate RPC error")
		} else if resp.GetStatus() != ndk.SdkMgrStatus_SDK_MGR_STATUS_SUCCESS {
			log.Warn().Str("error", resp.GetErrorStr()).Msg("TelemetryAddOrUpdate rejected")
		} else {
			log.Info().Int("count", len(states)).Msg("TelemetryAddOrUpdate succeeded")
		}
	}
}

func atomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(filename)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}
