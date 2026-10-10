package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	if strings.Contains(jsPath, ".interface{") {
		return 2
	}
	if strings.Contains(jsPath, ".address-family{") {
		return 1
	}
	if strings.Contains(jsPath, ".neighbor{") {
		return 3
	}
	if strings.Contains(jsPath, ".route{") && !strings.Contains(jsPath, ".topology{") {
		return 4
	}
	if strings.Contains(jsPath, ".static-neighbor{") {
		return 5
	}
	if strings.Contains(jsPath, ".topology{") {
		if strings.Contains(jsPath, "}.route{") {
			return 7
		}
		return 6
	}
	if strings.Contains(jsPath, ".traffic{") {
		return 8
	}
	return 0
}

func buildInterfaceData(
	normName string,
	ipAddr string,
	prefixLen uint32,
	rawOperState string,
	passive bool,
	bfdSessionState string,
	bfdRemoteAddr string,
	ic *InterfaceConfig,
	defIntf *DefaultInterfaceConfig,
	instAuth *AuthConfig,
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

	isPassive := passive
	if ic != nil && ic.Passive != nil {
		isPassive = *ic.Passive
	} else if defIntf != nil {
		isPassive = defIntf.Passive
	}

	helloInterval := uint16(5)
	if ic != nil && ic.HelloInterval != nil && *ic.HelloInterval > 0 {
		helloInterval = *ic.HelloInterval
	} else if defIntf != nil && defIntf.HelloInterval > 0 {
		helloInterval = defIntf.HelloInterval
	}

	holdTime := uint16(15)
	if ic != nil && ic.HoldTime != nil && *ic.HoldTime > 0 {
		holdTime = *ic.HoldTime
	} else if defIntf != nil && defIntf.HoldTime > 0 {
		holdTime = defIntf.HoldTime
	}

	splitHorizon := true
	if ic != nil && ic.SplitHorizon != nil {
		splitHorizon = *ic.SplitHorizon
	} else if defIntf != nil && defIntf.SplitHorizon != nil {
		splitHorizon = *defIntf.SplitHorizon
	}

	nextHopSelf := false
	if ic != nil && ic.NextHopSelf != nil {
		nextHopSelf = *ic.NextHopSelf
	} else if defIntf != nil && defIntf.NextHopSelf != nil {
		nextHopSelf = *defIntf.NextHopSelf
	}

	data := map[string]interface{}{
		"interface-name": normName,
		"admin-state":    adminState,
		"oper-state":     operState,
		"passive":        isPassive,
		"hello-interval": helloInterval,
		"hold-time":      holdTime,
		"split-horizon":  splitHorizon,
		"next-hop-self":  nextHopSelf,
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

	var authCfg *AuthConfig
	if ic != nil && ic.Authentication != nil && ic.Authentication.Mode != "" {
		authCfg = ic.Authentication
	} else if defIntf != nil && defIntf.Authentication != nil && defIntf.Authentication.Mode != "" {
		authCfg = defIntf.Authentication
	} else if instAuth != nil && instAuth.Mode != "" {
		authCfg = instAuth
	}
	if authCfg != nil {
		authMap := map[string]interface{}{
			"mode": authCfg.Mode,
		}
		if authCfg.Keychain != "" {
			authMap["keychain"] = authCfg.Keychain
		}
		if authCfg.AuthenticationKey != "" {
			authMap["authentication-key"] = authCfg.AuthenticationKey
		}
		data["authentication"] = authMap
	}

	bfdAdmin := "disable"
	bfdTx := uint32(1000000)
	bfdRx := uint32(1000000)
	bfdMult := uint8(3)
	if defIntf != nil && defIntf.Bfd != nil {
		if defIntf.Bfd.AdminState != "" {
			bfdAdmin = defIntf.Bfd.AdminState
		}
		if defIntf.Bfd.DesiredMinimumTxInterval != nil && *defIntf.Bfd.DesiredMinimumTxInterval > 0 {
			bfdTx = *defIntf.Bfd.DesiredMinimumTxInterval
		}
		if defIntf.Bfd.RequiredMinimumReceive != nil && *defIntf.Bfd.RequiredMinimumReceive > 0 {
			bfdRx = *defIntf.Bfd.RequiredMinimumReceive
		}
		if defIntf.Bfd.DetectionMultiplier != nil && *defIntf.Bfd.DetectionMultiplier > 0 {
			bfdMult = *defIntf.Bfd.DetectionMultiplier
		}
	}
	if ic != nil && ic.Bfd != nil {
		if ic.Bfd.AdminState != "" {
			bfdAdmin = ic.Bfd.AdminState
		}
		if ic.Bfd.DesiredMinimumTxInterval != nil && *ic.Bfd.DesiredMinimumTxInterval > 0 {
			bfdTx = *ic.Bfd.DesiredMinimumTxInterval
		}
		if ic.Bfd.RequiredMinimumReceive != nil && *ic.Bfd.RequiredMinimumReceive > 0 {
			bfdRx = *ic.Bfd.RequiredMinimumReceive
		}
		if ic.Bfd.DetectionMultiplier != nil && *ic.Bfd.DetectionMultiplier > 0 {
			bfdMult = *ic.Bfd.DetectionMultiplier
		}
	}

	bfdOper := "down"
	if bfdAdmin == "enable" && operState == "up" {
		bfdOper = "up"
	}
	data["bfd"] = map[string]interface{}{
		"admin-state":                 bfdAdmin,
		"oper-state":                  bfdOper,
		"desired-minimum-tx-interval": bfdTx,
		"required-minimum-receive":   bfdRx,
		"detection-multiplier":        bfdMult,
	}

	if bfdSessionState != "" {
		data["bfd-state"] = map[string]interface{}{
			"session-state":  bfdSessionState,
			"remote-address": bfdRemoteAddr,
		}
	}

	return data
}

func publishInterfaceSublists(
	ni string,
	normName string,
	operState string,
	defIntf *DefaultInterfaceConfig,
	ic *InterfaceConfig,
	instOperState string,
	instAfs []AddressFamilyConfig,
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
		if ic != nil {
			afEnabled = ic.IsAfiEnabled(afName, defAdmin)
			afPassive = ic.IsAfiPassive(afName, defPassive)
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
			"name":        afName,
			"admin-state": adminStateStr,
			"oper-state":  operStateStr,
			"passive":     afPassive,
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
		if b, err := json.Marshal(afData); err == nil {
			*states = append(*states, &ndk.TelemetryInfo{
				Key:  &ndk.TelemetryKey{JsPath: afIfKey},
				Data: &ndk.TelemetryData{JsonContent: string(b)},
			})
			log.Info().Str("key", afIfKey).Str("data", string(b)).Msg("Adding interface AF to telemetry")
		}
	}

	if ic != nil && len(ic.SummaryAddress) > 0 {
		for _, sa := range ic.SummaryAddress {
			if sa.Prefix == "" {
				continue
			}
			dist := sa.Distance
			if dist == 0 {
				dist = 5
			}
			saKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp.interface{.interface-name==\"%s\"}.summary-address{.prefix==\"%s\"}", ni, normName, sa.Prefix)
			currentKeys[saKey] = struct{}{}
			saData := map[string]interface{}{
				"prefix":   sa.Prefix,
				"distance": dist,
			}
			if b, err := json.Marshal(saData); err == nil {
				*states = append(*states, &ndk.TelemetryInfo{
					Key:  &ndk.TelemetryKey{JsPath: saKey},
					Data: &ndk.TelemetryData{JsonContent: string(b)},
				})
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
		ni                     string
		asn                    uint16
		routerId               string
		adminState             string
		operState              string
		networks               []string
		variance               uint8
		maximumPaths           uint8
		maximumHops            uint8
		ribScale               uint8
		wideMetrics            bool
		exportPolicy           string
		importPolicy           string
		gracefulRestart        *GracefulRestartConfig
		timers                 *TimersConfig
		metrics                *MetricsConfig
		metricWeights          *MetricsConfig
		authentication         *AuthConfig
		defaultIntf            *DefaultInterfaceConfig
		configuredInterfaces   map[string]*InterfaceConfig
		addressFamily          []AddressFamilyConfig
		staticNeighbors        map[string]*StaticNeighborConfig
		nbrList                []*NeighborInfo
		routeList              []*RouteInfo
		intfList               []*InterfaceInfo
		topoList               []*TopologyPrefixInfo
		trafficList            []*TrafficInfo
	}
	allInstData := make([]instData, 0, len(d.instances))
	for ni, inst := range d.instances {
		nbrList := make([]*NeighborInfo, 0, len(inst.neighbors))
		for _, n := range inst.neighbors {
			nbrList = append(nbrList, n)
		}
		routeList := make([]*RouteInfo, 0, len(inst.routes))
		for _, r := range inst.routes {
			routeList = append(routeList, r)
		}
		intfList := make([]*InterfaceInfo, 0, len(inst.interfaces))
		for _, i := range inst.interfaces {
			intfList = append(intfList, i)
		}
		topoList := make([]*TopologyPrefixInfo, 0, len(inst.topology))
		for _, t := range inst.topology {
			topoList = append(topoList, t)
		}
		trafficList := make([]*TrafficInfo, 0, len(inst.traffic))
		for _, tf := range inst.traffic {
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
		sort.Slice(trafficList, func(i, j int) bool { return normalizeIfName(trafficList[i].Interface) < normalizeIfName(trafficList[j].Interface) })
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
			"network-instance":  item.ni,
			"autonomous-system": item.asn,
			"router-id":         item.routerId,
			"admin-state":       item.adminState,
			"oper-state":        item.operState,
			"variance":          item.variance,
			"maximum-paths":     item.maximumPaths,
			"maximum-hops":      item.maximumHops,
			"rib-scale":         item.ribScale,
			"wide-metrics":      item.wideMetrics,
			"export-policy":     item.exportPolicy,
			"import-policy":     item.importPolicy,
			"graceful-restart":  item.gracefulRestart,
			"default-interface": item.defaultIntf,
			"timers":            item.timers,
			"metrics":           item.metrics,
			"networks":          item.networks,
			"static-neighbors":  item.staticNeighbors,
			"static-neighbor":   item.staticNeighbors,
			"interfaces":        item.intfList,
			"interface":         item.intfList,
			"neighbors":         item.nbrList,
			"neighbor":          item.nbrList,
			"routes":            item.routeList,
			"route":             item.routeList,
			"topology":          item.topoList,
			"traffic":           item.trafficList,
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
		_ = os.WriteFile("/var/run/srl_eigrp_state.json", b, 0644)
		_ = os.WriteFile("/tmp/srl_eigrp_state.json", b, 0644)
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
		defIntfPass := false
		defIntfHello := uint16(5)
		defIntfHold := uint16(15)
		defIntfSplit := true
		defIntfNextHop := false
		var defIntfBw *uint32
		var defIntfDelay *uint32
		var defIntfAuth *AuthConfig
		var defIntfBfd *BfdConfig
		if item.defaultIntf != nil {
			if item.defaultIntf.AdminState != "" {
				defIntfAdmin = item.defaultIntf.AdminState
			}
			defIntfPass = item.defaultIntf.Passive
			if item.defaultIntf.HelloInterval > 0 {
				defIntfHello = item.defaultIntf.HelloInterval
			}
			if item.defaultIntf.HoldTime > 0 {
				defIntfHold = item.defaultIntf.HoldTime
			}
			if item.defaultIntf.SplitHorizon != nil {
				defIntfSplit = *item.defaultIntf.SplitHorizon
			}
			if item.defaultIntf.NextHopSelf != nil {
				defIntfNextHop = *item.defaultIntf.NextHopSelf
			}
			defIntfBw = item.defaultIntf.Bandwidth
			defIntfDelay = item.defaultIntf.Delay
			defIntfAuth = item.defaultIntf.Authentication
			defIntfBfd = item.defaultIntf.Bfd
		}
		defOper := "up"
		if item.operState == "down" || defIntfAdmin == "disable" {
			defOper = "down"
		}
		defIntfData := map[string]interface{}{
			"admin-state":    defIntfAdmin,
			"oper-state":     defOper,
			"passive":        defIntfPass,
			"hello-interval": defIntfHello,
			"hold-time":      defIntfHold,
			"split-horizon":  defIntfSplit,
			"next-hop-self":  defIntfNextHop,
		}
		if defIntfBw != nil && *defIntfBw > 0 {
			defIntfData["bandwidth"] = *defIntfBw
		}
		if defIntfDelay != nil && *defIntfDelay > 0 {
			defIntfData["delay"] = *defIntfDelay
		}
		if defIntfAuth != nil && defIntfAuth.Mode != "" {
			aMap := map[string]interface{}{"mode": defIntfAuth.Mode}
			if defIntfAuth.Keychain != "" {
				aMap["keychain"] = defIntfAuth.Keychain
			}
			if defIntfAuth.AuthenticationKey != "" {
				aMap["authentication-key"] = defIntfAuth.AuthenticationKey
			}
			defIntfData["authentication"] = aMap
		}
		bfdDefAdmin := "disable"
		bfdDefTx := uint32(1000000)
		bfdDefRx := uint32(1000000)
		bfdDefMult := uint8(3)
		if defIntfBfd != nil {
			if defIntfBfd.AdminState != "" {
				bfdDefAdmin = defIntfBfd.AdminState
			}
			if defIntfBfd.DesiredMinimumTxInterval != nil && *defIntfBfd.DesiredMinimumTxInterval > 0 {
				bfdDefTx = *defIntfBfd.DesiredMinimumTxInterval
			}
			if defIntfBfd.RequiredMinimumReceive != nil && *defIntfBfd.RequiredMinimumReceive > 0 {
				bfdDefRx = *defIntfBfd.RequiredMinimumReceive
			}
			if defIntfBfd.DetectionMultiplier != nil && *defIntfBfd.DetectionMultiplier > 0 {
				bfdDefMult = *defIntfBfd.DetectionMultiplier
			}
		}
		bfdDefOper := "down"
		if bfdDefAdmin == "enable" && defOper == "up" {
			bfdDefOper = "up"
		}
		defIntfData["bfd"] = map[string]interface{}{
			"admin-state":                 bfdDefAdmin,
			"oper-state":                  bfdDefOper,
			"desired-minimum-tx-interval": bfdDefTx,
			"required-minimum-receive":   bfdDefRx,
			"detection-multiplier":        bfdDefMult,
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
		k6 := uint8(0)
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
			if item.metrics.K6 != nil {
				k6 = *item.metrics.K6
				extAttr = *item.metrics.K6
			}
			if item.metrics.RibScale != nil && *item.metrics.RibScale > 0 {
				ribScale = *item.metrics.RibScale
			}
		}
		metricsData := map[string]interface{}{
			"bandwidth":           bw,
			"load":                load,
			"delay":               delay,
			"reliability":         rel,
			"mtu":                 mtu,
			"k6":                  k6,
			"extended-attributes": extAttr,
			"rib-scale":           ribScale,
		}

		// Top-level delivery node (.network_instance{.name==ni}.protocols.eigrp)
		topKey := fmt.Sprintf(".network_instance{.name==\"%s\"}.protocols.eigrp", ni)
		currentKeys[topKey] = struct{}{}
		topData := map[string]interface{}{
			"admin-state":       item.adminState,
			"oper-state":        item.operState,
			"variance":          item.variance,
			"maximum-paths":     item.maximumPaths,
			"maximum-hops":      item.maximumHops,
			"rib-scale":         item.ribScale,
			"wide-metrics":      item.wideMetrics,
			"total-neighbors":   len(item.nbrList),
			"total-routes":      len(item.routeList),
			"total-interfaces":  len(item.intfList),
			"graceful-restart":  grData,
			"default-interface": defIntfData,
			"timers":            timersData,
			"metrics":           metricsData,
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
			authMd := n.AuthMode
			if authMd == "" {
				authMd = "none"
			}
			nbrData := map[string]interface{}{
				"ip-address":    n.IPAddress,
				"interface":     normalizeIfName(n.Interface),
				"state":         n.State,
				"hold-time":     n.HoldTime,
				"uptime":        fmt.Sprintf("%ds", n.Uptime),
				"srtt-ms":       n.SRTT,
				"rto-ms":        n.RTO,
				"bfd-state":     bfdSt,
				"restart-state": rstSt,
				"auth-mode":     authMd,
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
			pref := uint8(90)
			if r.External {
				pref = 170
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

			var bfdSessionState string
			var bfdRemoteAddr string
			for _, n := range item.nbrList {
				if normalizeIfName(n.Interface) == normName && n.BfdState != "" && n.BfdState != "disabled" {
					bfdSessionState = n.BfdState
					bfdRemoteAddr = n.IPAddress
					break
				}
			}

			intfData := buildInterfaceData(
				normName,
				i.IPAddress,
				i.PrefixLen,
				i.OperState,
				i.Passive,
				bfdSessionState,
				bfdRemoteAddr,
				ic,
				item.defaultIntf,
				item.authentication,
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
				item.operState,
				item.addressFamily,
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
				false,
				"",
				"",
				ic,
				item.defaultIntf,
				item.authentication,
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
				item.operState,
				item.addressFamily,
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
			afData := map[string]interface{}{
				"name":        afName,
				"admin-state": afAdmin,
				"oper-state":  afOper,
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
				"cr-packets":          tf.CRPackets,
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

	if len(delKeys) > 0 {
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
	if len(states) > 0 {
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
