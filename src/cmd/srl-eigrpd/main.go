package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

/*
#include <stdlib.h>
#include "srl_cshim.h"
*/
import "C"

const (
	ndkSocket = "unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053"
	appName   = "srl_eigrpd"
	version   = "0.1.0"
)

type RouteInfo struct {
	Prefix     string `json:"prefix"`
	NextHop    string `json:"next-hop"`
	Metric     uint32 `json:"metric"`
	WideMetric uint64 `json:"wide-metric"`
	External   bool   `json:"external"`
	Preference uint8  `json:"preference,omitempty"`
	Interface  string `json:"interface,omitempty"`
}

type NeighborInfo struct {
	IPAddress      string `json:"ip-address"`
	Interface      string `json:"interface"`
	State          string `json:"state"`
	HoldTime       uint16 `json:"hold-time"`
	Uptime         uint64 `json:"uptime"`
	SRTT           uint32 `json:"srtt-ms"`
	RTO            uint32 `json:"rto-ms"`
	BfdState       string `json:"bfd-state,omitempty"`
	RestartState   string `json:"restart-state,omitempty"`
	AuthMode       string `json:"auth-mode,omitempty"`
	OperDownReason string `json:"oper-down-reason,omitempty"`
}

type InterfaceInfo struct {
	Name           string `json:"name"`
	InterfaceName  string `json:"interface-name,omitempty"`
	AdminState     string `json:"admin-state,omitempty"`
	IPAddress      string `json:"ip-address"`
	PrefixLen      uint32 `json:"prefix-length"`
	IP6Address     string `json:"ip6-address,omitempty"`
	PrefixLen6     uint32 `json:"prefix-length6,omitempty"`
	OperState      string `json:"oper-state"`
	OperDownReason string `json:"oper-down-reason,omitempty"`
	BfdState       string `json:"bfd-state,omitempty"`
	AuthMode       string `json:"auth-mode,omitempty"`
	Passive        bool   `json:"passive"`
}

type TopologyRouteInfo struct {
	NextHop          string `json:"next-hop"`
	Interface        string `json:"interface"`
	Successor        bool   `json:"successor"`
	FeasibleSucc     bool   `json:"feasible-successor"`
	Distance         uint32 `json:"distance"`
	WideDistance     uint64 `json:"wide-distance"`
	ReportedDistance uint32 `json:"reported-distance"`
	WideRD           uint64 `json:"wide-reported-distance"`
}

type TopologyPrefixInfo struct {
	Destination    string               `json:"destination"`
	Active         bool                 `json:"active"`
	FD             uint32               `json:"feasible-distance"`
	WideFD         uint64               `json:"wide-feasible-distance"`
	SuccessorCount uint32               `json:"successor-count"`
	Routes         []*TopologyRouteInfo `json:"routes"`
}

type TrafficInfo struct {
	Interface       string `json:"interface"`
	ReliableMcast   uint64 `json:"reliable-multicast"`
	UnreliableMcast uint64 `json:"unreliable-multicast"`
	ReliableUcast   uint64 `json:"reliable-unicast"`
	UnreliableUcast uint64 `json:"unreliable-unicast"`
	Retransmissions uint64 `json:"retransmissions"`
	CRPackets       uint64 `json:"cr-packets"`
}

type IPCRequest struct {
	Action   string `json:"action"`
	Netinst  string `json:"netinst"`
	Neighbor string `json:"neighbor"`
}

type IPCResponse struct {
	Status   string `json:"status"`
	Affected int    `json:"affected,omitempty"`
	Message  string `json:"message"`
}

type EigrpInstance struct {
	netinst              string
	asn                  uint16
	routerId             string
	adminState           string
	operState            string
	networks             []string
	configuredInterfaces map[string]*InterfaceConfig
	defaultIntf          *DefaultInterfaceConfig
	exportPolicy         string
	importPolicy         string
	variance             uint8
	maximumPaths         uint8
	maximumHops          uint8
	ribScale             uint8
	preference           uint8
	externalPreference   uint8
	wideMetrics          bool
	hasV6                bool
	gracefulRestart      *GracefulRestartConfig
	metrics              *MetricsConfig
	metricWeights        *MetricsConfig
	timers               *TimersConfig
	authentication       *AuthConfig
	addressFamily        []AddressFamilyConfig
	restarting           bool
	bfdSessions          map[string]string
	staticNeighbors      map[string]*StaticNeighborConfig
	redistributedRoutes  map[string]string
	redistributedHashes  map[string]string

	routes     map[string]*RouteInfo
	neighbors  map[string]*NeighborInfo
	interfaces map[string]*InterfaceInfo
	topology   map[string]*TopologyPrefixInfo
	traffic    map[string]*TrafficInfo
	currentPfx *TopologyPrefixInfo

	tempNeighbors  map[string]*NeighborInfo
	tempInterfaces map[string]*InterfaceInfo
	tempTopology   map[string]*TopologyPrefixInfo
	tempTraffic    map[string]*TrafficInfo
	collecting     bool
}

func (inst *EigrpInstance) IsAfiEnabled(afi string) bool {
	if inst.adminState == "disable" || inst.asn == 0 {
		return false
	}
	if len(inst.addressFamily) > 0 {
		for _, af := range inst.addressFamily {
			if af.Name == afi {
				if af.AdminState != "" {
					return af.AdminState != "disable"
				}
				return true
			}
		}
		return false
	}
	// Default enabled for both ipv4-unicast and ipv6-unicast if no address-family explicitly configured
	return true
}

func (inst *EigrpInstance) SetAfiAdminState(afi string, state string) {
	for i, af := range inst.addressFamily {
		if af.Name == afi {
			inst.addressFamily[i].AdminState = state
			return
		}
	}
	inst.addressFamily = append(inst.addressFamily, AddressFamilyConfig{
		Name:       afi,
		AdminState: state,
	})
}

func (inst *EigrpInstance) GetAfiExportPolicy(afi string) string {
	for _, af := range inst.addressFamily {
		if af.Name == afi && af.ExportPolicy != "" {
			return af.ExportPolicy
		}
	}
	return inst.exportPolicy
}

func (inst *EigrpInstance) SetAfiExportPolicy(afi string, policy string) {
	for i, af := range inst.addressFamily {
		if af.Name == afi {
			inst.addressFamily[i].ExportPolicy = policy
			return
		}
	}
	inst.addressFamily = append(inst.addressFamily, AddressFamilyConfig{
		Name:         afi,
		ExportPolicy: policy,
	})
}

func (inst *EigrpInstance) GetAfiImportPolicy(afi string) string {
	for _, af := range inst.addressFamily {
		if af.Name == afi && af.ImportPolicy != "" {
			return af.ImportPolicy
		}
	}
	return inst.importPolicy
}

func (inst *EigrpInstance) SetAfiImportPolicy(afi string, policy string) {
	for i, af := range inst.addressFamily {
		if af.Name == afi {
			inst.addressFamily[i].ImportPolicy = policy
			return
		}
	}
	inst.addressFamily = append(inst.addressFamily, AddressFamilyConfig{
		Name:         afi,
		ImportPolicy: policy,
	})
}

func (inst *EigrpInstance) GetAfiPreference(afi string) uint8 {
	for _, af := range inst.addressFamily {
		if af.Name == afi && af.Preference > 0 {
			return af.Preference
		}
	}
	if inst.preference > 0 {
		return inst.preference
	}
	return 90
}

func (inst *EigrpInstance) SetAfiPreference(afi string, pref uint8) {
	for i, af := range inst.addressFamily {
		if af.Name == afi {
			inst.addressFamily[i].Preference = pref
			return
		}
	}
	inst.addressFamily = append(inst.addressFamily, AddressFamilyConfig{
		Name:       afi,
		Preference: pref,
	})
}

func (inst *EigrpInstance) GetAfiExternalPreference(afi string) uint8 {
	for _, af := range inst.addressFamily {
		if af.Name == afi && af.ExternalPreference > 0 {
			return af.ExternalPreference
		}
	}
	if inst.externalPreference > 0 {
		return inst.externalPreference
	}
	return 170
}

func (inst *EigrpInstance) SetAfiExternalPreference(afi string, extPref uint8) {
	for i, af := range inst.addressFamily {
		if af.Name == afi {
			inst.addressFamily[i].ExternalPreference = extPref
			return
		}
	}
	inst.addressFamily = append(inst.addressFamily, AddressFamilyConfig{
		Name:               afi,
		ExternalPreference: extPref,
	})
}

func (inst *EigrpInstance) SetAfiPreferences(afi string, pref, extPref uint8) {
	for i, af := range inst.addressFamily {
		if af.Name == afi {
			if pref > 0 {
				inst.addressFamily[i].Preference = pref
			}
			if extPref > 0 {
				inst.addressFamily[i].ExternalPreference = extPref
			}
			return
		}
	}
	inst.addressFamily = append(inst.addressFamily, AddressFamilyConfig{
		Name:               afi,
		Preference:         pref,
		ExternalPreference: extPref,
	})
}

func newEigrpInstance(netinst string) *EigrpInstance {
	return &EigrpInstance{
		netinst:              netinst,
		adminState:           "enable",
		operState:            "up",
		variance:             1,
		maximumPaths:         4,
		maximumHops:          100,
		ribScale:             128,
		preference:           90,
		externalPreference:   170,
		wideMetrics:          true,
		configuredInterfaces: make(map[string]*InterfaceConfig),
		staticNeighbors:      make(map[string]*StaticNeighborConfig),
		routes:               make(map[string]*RouteInfo),
		neighbors:            make(map[string]*NeighborInfo),
		interfaces:           make(map[string]*InterfaceInfo),
		topology:             make(map[string]*TopologyPrefixInfo),
		traffic:              make(map[string]*TrafficInfo),
		tempNeighbors:        make(map[string]*NeighborInfo),
		tempInterfaces:       make(map[string]*InterfaceInfo),
		tempTopology:         make(map[string]*TopologyPrefixInfo),
		tempTraffic:          make(map[string]*TrafficInfo),
		bfdSessions:          make(map[string]string),
		redistributedRoutes:  make(map[string]string),
		redistributedHashes:  make(map[string]string),
	}
}

func (inst *EigrpInstance) PrepareTelemetryCollection() {
	inst.tempNeighbors = make(map[string]*NeighborInfo)
	inst.tempInterfaces = make(map[string]*InterfaceInfo)
	inst.tempTopology = make(map[string]*TopologyPrefixInfo)
	inst.tempTraffic = make(map[string]*TrafficInfo)
	inst.collecting = true
}

func (inst *EigrpInstance) CommitTelemetryCollection() {
	if inst.tempNeighbors != nil {
		inst.neighbors = inst.tempNeighbors
	} else if inst.neighbors == nil {
		inst.neighbors = make(map[string]*NeighborInfo)
	}
	if inst.tempInterfaces != nil {
		inst.interfaces = inst.tempInterfaces
	} else if inst.interfaces == nil {
		inst.interfaces = make(map[string]*InterfaceInfo)
	}
	if inst.tempTopology != nil {
		inst.topology = inst.tempTopology
	} else if inst.topology == nil {
		inst.topology = make(map[string]*TopologyPrefixInfo)
	}
	if inst.tempTraffic != nil {
		inst.traffic = inst.tempTraffic
	} else if inst.traffic == nil {
		inst.traffic = make(map[string]*TrafficInfo)
	}
	inst.tempNeighbors = nil
	inst.tempInterfaces = nil
	inst.tempTopology = nil
	inst.tempTraffic = nil
	inst.collecting = false
}

type EigrpDaemon struct {
	conn           *grpc.ClientConn
	sdkClient      ndk.SdkMgrServiceClient
	routeClient    ndk.SdkMgrRouteServiceClient
	nhgClient      ndk.SdkMgrNextHopGroupServiceClient
	teleClient     ndk.SdkMgrTelemetryServiceClient
	notifClient    ndk.SdkNotificationServiceClient
	appId          uint32
	streamId       uint64
	mu             sync.RWMutex
	telemetryMu    sync.Mutex
	instances      map[string]*EigrpInstance
	learnedVlans   map[string]uint16
	prevTeleKeys   map[string]struct{}
	policies       map[string]*PolicyMetricConfig
	policyDefs     map[string]*PolicyDef
	redistChan     chan string
	fibSyncActive  bool
	routeWorkers   map[string]*routeQueueWorker
	routeWorkersMu sync.Mutex
	routeCache     map[string]*candidateRouteCacheEntry
	routeCacheMu   sync.RWMutex

	gnmiConn   *grpc.ClientConn
	gnmiClient gnmi.GNMIClient
	gnmiMu     sync.Mutex

	nhgMu        sync.Mutex
	prefixToNhg  map[string]string
	nhgRefCounts map[string]int

	appIdMu     sync.RWMutex
	appIdToName map[uint32]string

	netinstMu       sync.RWMutex
	netinstIdToName map[string]string
	netinstNameToId map[string]string

	candidateMu     sync.RWMutex
	candidateRoutes map[string]map[string]CandidateRoute
}

var daemonApp *EigrpDaemon

func (d *EigrpDaemon) resolveNetinstName(raw string) string {
	if raw == "" {
		return "default"
	}
	d.netinstMu.RLock()
	defer d.netinstMu.RUnlock()
	if d.netinstIdToName != nil {
		if name, ok := d.netinstIdToName[raw]; ok && name != "" {
			return name
		}
	}
	if raw == "10241" {
		return "default"
	}
	if raw == "10240" {
		return "mgmt"
	}
	return raw
}

func (d *EigrpDaemon) getNetinstId(name string) (string, bool) {
	d.netinstMu.RLock()
	defer d.netinstMu.RUnlock()
	if d.netinstNameToId != nil {
		if id, ok := d.netinstNameToId[name]; ok && id != "" {
			return id, true
		}
	}
	if name == "default" {
		return "10241", true
	}
	if name == "mgmt" {
		return "10240", true
	}
	return "", false
}

func (d *EigrpDaemon) HandleNetworkInstanceNotification(ni *ndk.NetworkInstanceNotification) {
	if ni == nil || ni.GetKey() == nil {
		return
	}
	name := ni.GetKey().GetInstanceName()
	if name == "" {
		return
	}
	op := ni.GetOp()

	d.netinstMu.Lock()
	if d.netinstIdToName == nil {
		d.netinstIdToName = make(map[string]string)
	}
	if d.netinstNameToId == nil {
		d.netinstNameToId = make(map[string]string)
	}

	if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
		if idStr, ok := d.netinstNameToId[name]; ok {
			delete(d.netinstIdToName, idStr)
		}
		delete(d.netinstNameToId, name)
		d.netinstMu.Unlock()
		return
	}

	var idStr string
	if ni.GetData() != nil {
		id := ni.GetData().GetNetworkInstanceId()
		idStr = strconv.FormatUint(uint64(id), 10)
		d.netinstIdToName[idStr] = name
		d.netinstNameToId[name] = idStr
		log.Info().Str("netinst", name).Str("id", idStr).Msg("Learned network-instance mapping")
	}
	d.netinstMu.Unlock()

	// If candidate routes were stored under idStr before the network-instance mapping arrived, migrate them to name
	if idStr != "" && idStr != name {
		d.candidateMu.Lock()
		if orphanRoutes, exists := d.candidateRoutes[idStr]; exists && len(orphanRoutes) > 0 {
			if d.candidateRoutes[name] == nil {
				d.candidateRoutes[name] = make(map[string]CandidateRoute)
			}
			for k, v := range orphanRoutes {
				d.candidateRoutes[name][k] = v
			}
			delete(d.candidateRoutes, idStr)
		}
		d.candidateMu.Unlock()
	}

	d.TriggerRedistSync(name)
}

func (d *EigrpDaemon) GetInstance(netinst string) *EigrpInstance {
	if netinst == "" {
		netinst = "default"
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.instances == nil {
		return nil
	}
	return d.instances[netinst]
}

func (d *EigrpDaemon) GetOrCreateInstance(netinst string) *EigrpInstance {
	if netinst == "" {
		netinst = "default"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.instances == nil {
		d.instances = make(map[string]*EigrpInstance)
	}
	inst, exists := d.instances[netinst]
	if !exists {
		inst = newEigrpInstance(netinst)
		d.instances[netinst] = inst
	}
	return inst
}

func (d *EigrpDaemon) DeleteInstance(netinst string) {
	if netinst == "" {
		netinst = "default"
	}
	d.StopRouteWorker(netinst)
	d.InvalidateCandidateRouteCache(netinst)
	d.mu.Lock()
	if d.instances != nil {
		delete(d.instances, netinst)
	}
	d.mu.Unlock()

	d.candidateMu.Lock()
	if d.candidateRoutes != nil {
		delete(d.candidateRoutes, netinst)
	}
	d.candidateMu.Unlock()
}

func (d *EigrpDaemon) CollectAndPublish(ctx context.Context) {
	d.telemetryMu.Lock()
	defer d.telemetryMu.Unlock()

	d.mu.RLock()
	netinsts := make([]string, 0, len(d.instances))
	for ni := range d.instances {
		netinsts = append(netinsts, ni)
	}
	d.mu.RUnlock()

	for _, netinst := range netinsts {
		inst := d.GetInstance(netinst)
		if inst == nil {
			continue
		}
		cNetinst := C.CString(netinst)
		d.mu.Lock()
		inst.PrepareTelemetryCollection()
		d.mu.Unlock()

		d.mu.RLock()
		adminDisabled := (inst.adminState == "disable" || inst.asn == 0)
		d.mu.RUnlock()

		if !adminDisabled {
			C.srlShimInterfacesScan(cNetinst)
			C.srlShimInterfacesReport(cNetinst)
			C.srlShimNeighborsReport(cNetinst)
			C.srlShimTopologyReport(cNetinst)
			C.srlShimTrafficReport(cNetinst)
		} else {
			d.mu.Lock()
			inst.routes = make(map[string]*RouteInfo)
			d.mu.Unlock()
		}
		C.free(unsafe.Pointer(cNetinst))

		d.mu.Lock()
		inst.CommitTelemetryCollection()
		d.mu.Unlock()
	}

	d.publishTelemetryLocked(ctx)
}

func (d *EigrpDaemon) BfdSessionAddOrUpdate(netinst, peerIP, ifname, adminState string, txInterval, rxInterval uint32, mult uint8) error {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()

	if adminState == "enable" {
		cur := inst.bfdSessions[peerIP]
		if cur == "" || cur == "disabled" {
			inst.bfdSessions[peerIP] = "not-tracked"
		}
		if nbr, ok := inst.neighbors[peerIP]; ok {
			nbr.BfdState = inst.bfdSessions[peerIP]
		}
		if inst.collecting && inst.tempNeighbors != nil {
			if nbr, ok := inst.tempNeighbors[peerIP]; ok {
				nbr.BfdState = inst.bfdSessions[peerIP]
			}
		}
	} else {
		inst.bfdSessions[peerIP] = "disabled"
		if nbr, ok := inst.neighbors[peerIP]; ok {
			nbr.BfdState = "disabled"
		}
		if inst.collecting && inst.tempNeighbors != nil {
			if nbr, ok := inst.tempNeighbors[peerIP]; ok {
				nbr.BfdState = "disabled"
			}
		}
	}
	return nil
}

func (d *EigrpDaemon) OnNeighborReport(netinst, ip, ifname, state string, hold uint16, uptime uint64, srtt, rto uint32, bfdState, restartState, authMode string) {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()

	normIf := normalizeIfName(ifname)
	var ic *InterfaceConfig
	if c, ok := inst.configuredInterfaces[ifname]; ok {
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
		return
	}

	afiName := "ipv4-unicast"
	if strings.Contains(ip, ":") {
		afiName = "ipv6-unicast"
	}
	if !inst.IsAfiEnabled(afiName) {
		return
	}
	defPassive := false
	if inst.defaultIntf != nil {
		defPassive = inst.defaultIntf.IsAfiPassive(afiName)
	}
	isPassive := ic.IsAfiPassive(afiName, defPassive)
	if isPassive {
		return
	}

	// Check whether BFD is enabled for this interface or instance
	bfdEnabled := false
	bfd := ic.GetAfiBfd(afiName, inst.defaultIntf)
	if bfd != nil && bfd.AdminState == "enable" {
		bfdEnabled = true
	} else if inst.defaultIntf != nil {
		bfdDef := inst.defaultIntf.GetAfiBfd(afiName)
		if bfdDef != nil && bfdDef.AdminState == "enable" {
			bfdEnabled = true
		}
	}

	if bfdEnabled {
		if sess, ok := inst.bfdSessions[ip]; ok && sess != "" && sess != "disabled" {
			bfdState = sess
		} else {
			bfdState = "not-tracked"
			inst.bfdSessions[ip] = "not-tracked"
		}
	} else {
		bfdState = "disabled"
		inst.bfdSessions[ip] = "disabled"
	}

	// Check interface config for auth mode fallback
	if authMode == "" || authMode == "none" {
		auth := ic.GetAfiAuthentication(afiName, inst.defaultIntf, inst.authentication)
		if auth != nil && auth.Mode != "" {
			authMode = auth.Mode
		} else if inst.defaultIntf != nil {
			authDef := inst.defaultIntf.GetAfiAuthentication(afiName)
			if authDef != nil && authDef.Mode != "" {
				authMode = authDef.Mode
			} else if inst.authentication != nil && inst.authentication.Mode != "" {
				authMode = inst.authentication.Mode
			}
		} else if inst.authentication != nil && inst.authentication.Mode != "" {
			authMode = inst.authentication.Mode
		}
	}

	info := &NeighborInfo{
		IPAddress:    ip,
		Interface:    ifname,
		State:        state,
		HoldTime:     hold,
		Uptime:       uptime,
		SRTT:         srtt,
		RTO:          rto,
		BfdState:     bfdState,
		RestartState: restartState,
		AuthMode:     authMode,
	}
	if inst.collecting {
		inst.tempNeighbors[ip] = info
	} else {
		inst.neighbors[ip] = info
	}
}

func (d *EigrpDaemon) OnInterfaceReport(netinst, name, ipAddr string, prefixlen uint32, operState string) {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()
	normIf := normalizeIfName(name)
	bfdState := "disabled"
	for _, n := range inst.neighbors {
		if normalizeIfName(n.Interface) == normIf && n.BfdState != "" && n.BfdState != "disabled" {
			bfdState = n.BfdState
			break
		}
	}
	if bfdState == "disabled" && inst.collecting && inst.tempNeighbors != nil {
		for _, n := range inst.tempNeighbors {
			if normalizeIfName(n.Interface) == normIf && n.BfdState != "" && n.BfdState != "disabled" {
				bfdState = n.BfdState
				break
			}
		}
	}
	if bfdState == "disabled" {
		if cur, ok := inst.bfdSessions[name]; ok {
			bfdState = cur
		} else if cur, ok := inst.bfdSessions[normIf]; ok {
			bfdState = cur
		}
	}
	afi := "ipv4-unicast"
	if strings.Contains(ipAddr, ":") {
		afi = "ipv6-unicast"
	}

	var ic *InterfaceConfig
	if c, ok := inst.configuredInterfaces[name]; ok {
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
		return
	}

	authMode := "none"
	auth := ic.GetAfiAuthentication(afi, inst.defaultIntf, inst.authentication)
	if auth != nil && auth.Mode != "" {
		authMode = auth.Mode
	}

	defPassive := false
	if inst.defaultIntf != nil {
		defPassive = inst.defaultIntf.IsAfiPassive(afi)
	}
	isPassive := ic.IsAfiPassive(afi, defPassive)

	defAdmin := "enable"
	if inst.defaultIntf != nil && inst.defaultIntf.AdminState != "" {
		defAdmin = inst.defaultIntf.AdminState
	}
	adminState := "enable"
	if !ic.IsAfiEnabled(afi, defAdmin) {
		adminState = "disable"
	}

	targetMap := inst.interfaces
	if inst.collecting {
		targetMap = inst.tempInterfaces
	}

	info, exists := targetMap[name]
	if !exists {
		info = &InterfaceInfo{
			Name:          name,
			InterfaceName: normIf,
			AdminState:    adminState,
			OperState:     operState,
			BfdState:      bfdState,
			AuthMode:      authMode,
			Passive:       isPassive,
		}
		targetMap[name] = info
	} else {
		info.InterfaceName = normIf
		if operState == "Up" || operState == "up" {
			info.OperState = operState
		}
		if adminState != "" {
			info.AdminState = adminState
		}
		if bfdState != "disabled" {
			info.BfdState = bfdState
		}
		if authMode != "none" {
			info.AuthMode = authMode
		}
		info.Passive = isPassive
	}

	if strings.Contains(ipAddr, ":") {
		info.IP6Address = ipAddr
		info.PrefixLen6 = prefixlen
		if info.IPAddress == "" {
			info.IPAddress = ipAddr
			info.PrefixLen = prefixlen
		}
	} else {
		info.IPAddress = ipAddr
		info.PrefixLen = prefixlen
	}
}

func (d *EigrpDaemon) OnTopologyPrefix(netinst, prefix string, active bool, fd uint32, wideFd uint64, succCount uint32) {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()
	afiName := "ipv4-unicast"
	if strings.Contains(prefix, ":") {
		afiName = "ipv6-unicast"
	}
	if !inst.IsAfiEnabled(afiName) {
		inst.currentPfx = nil
		return
	}
	p := &TopologyPrefixInfo{
		Destination:    prefix,
		Active:         active,
		FD:             fd,
		WideFD:         wideFd,
		SuccessorCount: succCount,
		Routes:         make([]*TopologyRouteInfo, 0),
	}
	if inst.collecting {
		inst.tempTopology[prefix] = p
	} else {
		inst.topology[prefix] = p
	}
	inst.currentPfx = p
}

func (d *EigrpDaemon) OnTopologyRoute(netinst, nexthop, ifname string, isSucc, isFeasSucc bool, dist uint32, wideDist uint64, rd uint32, wideRd uint64) {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()
	if inst.currentPfx != nil {
		inst.currentPfx.Routes = append(inst.currentPfx.Routes, &TopologyRouteInfo{
			NextHop:          nexthop,
			Interface:        ifname,
			Successor:        isSucc,
			FeasibleSucc:     isFeasSucc,
			Distance:         dist,
			WideDistance:     wideDist,
			ReportedDistance: rd,
			WideRD:           wideRd,
		})
	}
}

func (d *EigrpDaemon) OnTrafficReport(netinst, ifname string, rmcast, umcast, rucast, uucast, rexmits, cr uint64) {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()
	normIf := normalizeIfName(ifname)
	var ic *InterfaceConfig
	if c, ok := inst.configuredInterfaces[ifname]; ok {
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
		return
	}
	info := &TrafficInfo{
		Interface:       ifname,
		ReliableMcast:   rmcast,
		UnreliableMcast: umcast,
		ReliableUcast:   rucast,
		UnreliableUcast: uucast,
		Retransmissions: rexmits,
		CRPackets:       cr,
	}
	if inst.collecting {
		inst.tempTraffic[ifname] = info
	} else {
		inst.traffic[ifname] = info
	}
}

func (d *EigrpDaemon) StartIPCServer(ctx context.Context) {
	sockPath := "/var/run/srl_eigrpd_ipc.sock"
	_ = os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to start IPC listener")
		return
	}
	_ = os.Chmod(sockPath, 0660)
	targetGid := -1
	if grp, err := user.LookupGroup("srlinux"); err == nil {
		if gid, err := strconv.Atoi(grp.Gid); err == nil {
			targetGid = gid
		}
	} else if grp, err := user.LookupGroup("root"); err == nil {
		if gid, err := strconv.Atoi(grp.Gid); err == nil {
			targetGid = gid
		}
	}
	if targetGid != -1 {
		_ = os.Chown(sockPath, -1, targetGid)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
		_ = os.Remove(sockPath)
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go d.handleIPC(conn)
		}
	}()
}

func (d *EigrpDaemon) handleIPC(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(conn)
	var req IPCRequest
	if err := decoder.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:  "error",
			Message: err.Error(),
		})
		return
	}

	netinst := req.Netinst
	if netinst == "" {
		netinst = "default"
	}

	switch req.Action {
	case "clear-neighbor":
		if req.Neighbor != "" && req.Neighbor != "*" && req.Neighbor != "all" {
			if ip := net.ParseIP(req.Neighbor); ip == nil {
				_ = json.NewEncoder(conn).Encode(IPCResponse{
					Status:  "error",
					Message: fmt.Sprintf("Invalid IPv4 address or IPv6 address '%s'", req.Neighbor),
				})
				return
			}
		}
		cNetinst := C.CString(netinst)
		cNbr := C.CString(req.Neighbor)
		affected := int(C.srlShimNeighborClear(cNetinst, cNbr))
		C.free(unsafe.Pointer(cNetinst))
		C.free(unsafe.Pointer(cNbr))

		if affected < 0 {
			_ = json.NewEncoder(conn).Encode(IPCResponse{
				Status:  "error",
				Message: fmt.Sprintf("Failed to clear neighbor '%s' in network-instance %s", req.Neighbor, netinst),
			})
			return
		}

		if req.Neighbor != "" && req.Neighbor != "*" && req.Neighbor != "all" {
			if affected == 0 {
				_ = json.NewEncoder(conn).Encode(IPCResponse{
					Status:   "error",
					Affected: 0,
					Message:  fmt.Sprintf("Neighbor %s not found in network-instance %s", req.Neighbor, netinst),
				})
				return
			}
			msg := fmt.Sprintf("Cleared neighbor %s in network-instance %s", req.Neighbor, netinst)
			_ = json.NewEncoder(conn).Encode(IPCResponse{
				Status:   "ok",
				Affected: affected,
				Message:  msg,
			})
			go d.CollectAndPublish(context.Background())
			return
		}

		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:   "ok",
			Affected: affected,
			Message:  fmt.Sprintf("Cleared %d neighbor(s) in network-instance %s", affected, netinst),
		})
		go d.CollectAndPublish(context.Background())

	case "restart":
		cNetinst := C.CString(netinst)
		cNbr := C.CString("all")
		affected := int(C.srlShimNeighborClear(cNetinst, cNbr))
		C.free(unsafe.Pointer(cNetinst))
		C.free(unsafe.Pointer(cNbr))
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:   "ok",
			Affected: affected,
			Message:  fmt.Sprintf("EIGRP protocol restarted on network-instance %s (%d neighbors reset)", netinst, affected),
		})
		go d.CollectAndPublish(context.Background())

	case "bfd-down":
		targetNbr := req.Neighbor
		if targetNbr == "" {
			targetNbr = "*"
		}
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		if targetNbr != "*" && targetNbr != "all" {
			inst.bfdSessions[targetNbr] = "down"
		} else {
			for n := range inst.neighbors {
				inst.bfdSessions[n] = "down"
			}
		}
		d.mu.Unlock()

		cNetinst := C.CString(netinst)
		cNbr := C.CString(targetNbr)
		affected := int(C.srlShimNeighborClear(cNetinst, cNbr))
		C.free(unsafe.Pointer(cNetinst))
		C.free(unsafe.Pointer(cNbr))

		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:   "ok",
			Affected: affected,
			Message:  fmt.Sprintf("Triggered BFD down transition for neighbor %s in %s (tore down %d neighbors)", targetNbr, netinst, affected),
		})
		go d.CollectAndPublish(context.Background())

	case "planned-restart":
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		inst.restarting = true
		restartTimeSec := 120
		if inst.gracefulRestart != nil && inst.gracefulRestart.RestartTime > 0 {
			restartTimeSec = int(inst.gracefulRestart.RestartTime)
		}
		d.mu.Unlock()

		cNetinst := C.CString(netinst)
		C.srlShimGracefulShutdown(cNetinst)
		cNbr := C.CString("all")
		affected := int(C.srlShimNeighborClear(cNetinst, cNbr))
		C.free(unsafe.Pointer(cNetinst))
		C.free(unsafe.Pointer(cNbr))

		time.AfterFunc(time.Duration(restartTimeSec)*time.Second, func() {
			d.mu.Lock()
			if inst.restarting {
				inst.restarting = false
				log.Info().Str("netinst", netinst).Msg("Graceful restart timer expired; exiting restart state")
			}
			d.mu.Unlock()
		})

		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:   "ok",
			Affected: affected,
			Message:  fmt.Sprintf("Planned graceful restart initiated for network-instance %s; FIB routes preserved", netinst),
		})
		go d.CollectAndPublish(context.Background())

	case "status":
		inst := d.GetInstance(netinst)
		d.mu.RLock()
		nbrCount := 0
		routeCount := 0
		asn := uint16(0)
		rid := ""
		if inst != nil {
			nbrCount = len(inst.neighbors)
			routeCount = len(inst.routes)
			asn = inst.asn
			rid = inst.routerId
		}
		d.mu.RUnlock()
		_ = json.NewEncoder(conn).Encode(map[string]interface{}{
			"status":            "ok",
			"network-instance":  netinst,
			"autonomous-system": asn,
			"router-id":         rid,
			"neighbors":         nbrCount,
			"routes":            routeCount,
		})

	default:
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:  "error",
			Message: fmt.Sprintf("Unknown action: %s", req.Action),
		})
	}
}

func logMessage(level int, msg string) {
	log.Info().Str("source", "cshim").Int("level", level).Msg(msg)
}

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version" {
			fmt.Printf("srl-eigrpd version %s\n", version)
			os.Exit(0)
		}
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	log.Info().Str("version", version).Msg("Starting Nokia SR Linux EIGRP NDK Daemon...")

	if v := os.Getenv("SRL_EIGRP_DISABLE_PKT_FD"); v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
		log.Info().Msg("AF_PACKET packet socket disabled by SRL_EIGRP_DISABLE_PKT_FD environment variable")
		C.srlShimSetPktFdDisabled(C.bool(true))
	}

	C.srlShimInit()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var conn *grpc.ClientConn
	agentInterceptor := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "agent_name", appName)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
	agentStreamInterceptor := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, "agent_name", appName)
		return streamer(ctx, desc, cc, method, opts...)
	}

	for {
		dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
		var err error
		conn, err = grpc.DialContext(dialCtx, ndkSocket,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
			grpc.WithUnaryInterceptor(agentInterceptor),
			grpc.WithStreamInterceptor(agentStreamInterceptor),
		)
		dialCancel()
		if err == nil {
			log.Info().Msg("Connected to NDK gRPC service manager")
			break
		}
		log.Warn().Err(err).Msg("Waiting for NDK gRPC manager socket...")
		select {
		case <-ctx.Done():
			C.srlShimFinish()
			return
		case <-time.After(2 * time.Second):
		}
	}

	daemonApp = &EigrpDaemon{
		conn:            conn,
		sdkClient:       ndk.NewSdkMgrServiceClient(conn),
		routeClient:     ndk.NewSdkMgrRouteServiceClient(conn),
		nhgClient:       ndk.NewSdkMgrNextHopGroupServiceClient(conn),
		teleClient:      ndk.NewSdkMgrTelemetryServiceClient(conn),
		notifClient:     ndk.NewSdkNotificationServiceClient(conn),
		instances:       make(map[string]*EigrpInstance),
		learnedVlans:    make(map[string]uint16),
		prevTeleKeys:    make(map[string]struct{}),
		policies:        make(map[string]*PolicyMetricConfig),
		policyDefs:      make(map[string]*PolicyDef),
		redistChan:      make(chan string, 32),
		routeWorkers:    make(map[string]*routeQueueWorker),
		routeCache:      make(map[string]*candidateRouteCacheEntry),
		prefixToNhg:     make(map[string]string),
		nhgRefCounts:    make(map[string]int),
		appIdToName:     make(map[uint32]string),
		candidateRoutes: make(map[string]map[string]CandidateRoute),
		netinstIdToName: map[string]string{
			"10241": "default",
			"10240": "mgmt",
			"10242": "vrf-1",
		},
		netinstNameToId: map[string]string{
			"default": "10241",
			"mgmt":    "10240",
			"vrf-1":   "10242",
		},
	}

	daemonApp.Register(ctx)

	daemonApp.FibSyncStart(ctx)
	daemonApp.ScheduleFibSyncEnd(10 * time.Second)

	if err := daemonApp.InitNotificationStream(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize notification stream")
	}
	go daemonApp.RunNotificationLoop(ctx)

	daemonApp.StartIPCServer(ctx)
	go daemonApp.TelemetryWorker(ctx)
	go daemonApp.RedistributionWorker(ctx)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Info().Str("signal", sig.String()).Msg("Shutting down srl-eigrpd...")
	daemonApp.StopAllRouteWorkers()
	daemonApp.FibSyncEnd(context.Background())
	C.srlShimFinish()
	if conn != nil {
		conn.Close()
	}
	daemonApp.gnmiMu.Lock()
	if daemonApp.gnmiConn != nil {
		daemonApp.gnmiConn.Close()
	}
	daemonApp.gnmiMu.Unlock()
	os.Exit(0)
}

func (d *EigrpDaemon) Register(ctx context.Context) error {
	req := &ndk.AgentRegistrationRequest{
		WaitConfigAck: false,
	}
	resp, err := d.sdkClient.AgentRegister(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("NDK registration failed")
		return err
	}
	d.appId = resp.AppId
	log.Info().Uint32("app_id", d.appId).Msg("Successfully registered with SR Linux NDK Manager")

	delReq := &ndk.TelemetryDeleteRequest{
		Keys: []*ndk.TelemetryKey{
			{JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.state"},
		},
	}
	_, _ = d.teleClient.TelemetryDelete(ctx, delReq)
	return nil
}

func (d *EigrpDaemon) InitNotificationStream(ctx context.Context) error {
	// Step 1: Create notification stream
	createReq := &ndk.NotificationRegisterRequest{
		Op: ndk.NotificationRegisterRequest_OPERATION_CREATE,
	}
	resp, err := d.sdkClient.NotificationRegister(ctx, createReq)
	if err != nil || resp.GetStatus() != ndk.SdkMgrStatus_SDK_MGR_STATUS_SUCCESS {
		log.Error().Err(err).Msg("Failed to create notification stream")
		return err
	}
	d.streamId = resp.StreamId
	log.Info().Uint64("stream_id", d.streamId).Msg("Created NDK notification stream")

	// Step 2: Add subscription for Config service to this stream
	subReq := &ndk.NotificationRegisterRequest{
		Op:       ndk.NotificationRegisterRequest_OPERATION_ADD_SUBSCRIPTION,
		StreamId: d.streamId,
		SubscriptionTypes: &ndk.NotificationRegisterRequest_Config{
			Config: &ndk.ConfigSubscriptionRequest{},
		},
	}
	subResp, err := d.sdkClient.NotificationRegister(ctx, subReq)
	if err != nil || subResp.GetStatus() != ndk.SdkMgrStatus_SDK_MGR_STATUS_SUCCESS {
		log.Error().Err(err).Msg("Failed to add configuration subscription to stream")
		return err
	}
	log.Info().Msg("Successfully registered configuration subscription with NDK")

	// Step 3: Add subscription for BFD session notifications
	bfdSubReq := &ndk.NotificationRegisterRequest{
		Op:       ndk.NotificationRegisterRequest_OPERATION_ADD_SUBSCRIPTION,
		StreamId: d.streamId,
		SubscriptionTypes: &ndk.NotificationRegisterRequest_BfdSession{
			BfdSession: &ndk.BfdSessionSubscriptionRequest{},
		},
	}
	bfdResp, err := d.sdkClient.NotificationRegister(ctx, bfdSubReq)
	if err != nil || bfdResp.GetStatus() != ndk.SdkMgrStatus_SDK_MGR_STATUS_SUCCESS {
		log.Warn().Err(err).Msg("Failed to add BFD session subscription to stream (may be unsupported or inactive)")
	} else {
		log.Info().Msg("Successfully registered BFD session subscription with NDK")
	}

	// Step 4: Add subscription for IP route notifications
	routeSubReq := &ndk.NotificationRegisterRequest{
		Op:       ndk.NotificationRegisterRequest_OPERATION_ADD_SUBSCRIPTION,
		StreamId: d.streamId,
		SubscriptionTypes: &ndk.NotificationRegisterRequest_Route{
			Route: &ndk.IpRouteSubscriptionRequest{},
		},
	}
	routeResp, err := d.sdkClient.NotificationRegister(ctx, routeSubReq)
	if err != nil || routeResp.GetStatus() != ndk.SdkMgrStatus_SDK_MGR_STATUS_SUCCESS {
		log.Warn().Err(err).Msg("Failed to add route subscription to stream (will rely on periodic sync)")
	} else {
		log.Info().Msg("Successfully registered IP route subscription with NDK")
	}

	// Step 5: Add subscription for AppId notifications
	appIdSubReq := &ndk.NotificationRegisterRequest{
		Op:       ndk.NotificationRegisterRequest_OPERATION_ADD_SUBSCRIPTION,
		StreamId: d.streamId,
		SubscriptionTypes: &ndk.NotificationRegisterRequest_AppId{
			AppId: &ndk.AppIdentSubscriptionRequest{},
		},
	}
	appIdResp, err := d.sdkClient.NotificationRegister(ctx, appIdSubReq)
	if err != nil || appIdResp.GetStatus() != ndk.SdkMgrStatus_SDK_MGR_STATUS_SUCCESS {
		log.Warn().Err(err).Msg("Failed to add AppId subscription to stream")
	} else {
		log.Info().Msg("Successfully registered AppId subscription with NDK")
	}
	return nil
}

func (d *EigrpDaemon) reconnectNDK(ctx context.Context) error {
	if err := d.Register(ctx); err != nil {
		return err
	}
	return d.InitNotificationStream(ctx)
}

func (d *EigrpDaemon) RunNotificationLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		stream, err := d.notifClient.NotificationStream(ctx, &ndk.NotificationStreamRequest{StreamId: d.streamId})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to open notification stream; re-registering with NDK SDK Manager...")
			if recErr := d.reconnectNDK(ctx); recErr != nil {
				log.Warn().Err(recErr).Msg("reconnectNDK failed during open stream; will retry")
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		log.Info().Uint64("stream_id", d.streamId).Msg("Notification stream active and listening for events")

		for {
			ev, err := stream.Recv()
			if err != nil {
				log.Warn().Err(err).Msg("Notification stream terminated, reconnecting...")
				break
			}
			for _, n := range ev.GetNotifications() {
				if cfg := n.GetConfig(); cfg != nil {
					d.HandleConfigNotification(cfg)
				}
				if bfd := n.GetBfdSession(); bfd != nil {
					d.HandleBfdNotification(bfd)
				}
				if appId := n.GetAppId(); appId != nil {
					d.HandleAppIdNotification(appId)
				}
				if ni := n.GetNetworkInstance(); ni != nil {
					d.HandleNetworkInstanceNotification(ni)
				}
				if r := n.GetRoute(); r != nil {
					d.HandleRouteNotification(r)
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}

		// Re-execute Register() and InitNotificationStream() so a new stream ID and subscriptions are established
		log.Info().Msg("Re-executing Register() and InitNotificationStream() following stream disconnect")
		if recErr := d.reconnectNDK(ctx); recErr != nil {
			log.Warn().Err(recErr).Msg("Failed to re-initialize notification stream after disconnect; will retry")
		}
	}
}

func (d *EigrpDaemon) HandleAppIdNotification(appId *ndk.AppIdentNotification) {
	if appId == nil || appId.GetKey() == nil {
		return
	}
	id := appId.GetKey().GetId()
	op := appId.GetOp()
	var newName string
	d.appIdMu.Lock()
	if d.appIdToName == nil {
		d.appIdToName = make(map[uint32]string)
	}
	if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
		delete(d.appIdToName, id)
	} else if appId.GetData() != nil {
		newName = appId.GetData().GetName()
		d.appIdToName[id] = newName
	}
	d.appIdMu.Unlock()

	if newName != "" {
		d.candidateMu.Lock()
		for _, netinstRoutes := range d.candidateRoutes {
			for pfx, cr := range netinstRoutes {
				if cr.OwnerId == id {
					cr.RouteOwner = newName
					if cr.RouteType == "" || cr.RouteType == "static" {
						cr.RouteType = newName
					}
					netinstRoutes[pfx] = cr
				}
			}
		}
		d.candidateMu.Unlock()
	}

	d.TriggerRedistSync("all")
}

func (d *EigrpDaemon) getAppOwner(id uint32) string {
	d.appIdMu.RLock()
	defer d.appIdMu.RUnlock()
	if d.appIdToName == nil {
		return ""
	}
	return d.appIdToName[id]
}

func (d *EigrpDaemon) HandleRouteNotification(r *ndk.IpRouteNotification) {
	if r == nil || r.GetKey() == nil {
		return
	}
	key := r.GetKey()
	rawNetinst := key.GetNetworkInstanceName()
	netinst := d.resolveNetinstName(rawNetinst)
	if netinst == "" {
		netinst = "default"
	}
	pfxPb := key.GetIpPrefix()
	if pfxPb == nil || pfxPb.GetIpAddr() == nil {
		return
	}
	ipBytes := pfxPb.GetIpAddr().GetIpAddress()
	if len(ipBytes) == 0 {
		return
	}
	prefix := fmt.Sprintf("%s/%d", net.IP(ipBytes).String(), pfxPb.GetPrefixLength())
	isV6 := strings.Contains(prefix, ":")
	afi := "ipv4-unicast"
	if isV6 {
		afi = "ipv6-unicast"
	}

	op := r.GetOp()
	d.candidateMu.Lock()
	if d.candidateRoutes == nil {
		d.candidateRoutes = make(map[string]map[string]CandidateRoute)
	}
	if _, ok := d.candidateRoutes[netinst]; !ok {
		d.candidateRoutes[netinst] = make(map[string]CandidateRoute)
	}

	if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
		delete(d.candidateRoutes[netinst], prefix)
		if rawNetinst != "" && rawNetinst != netinst {
			if _, ok := d.candidateRoutes[rawNetinst]; ok {
				delete(d.candidateRoutes[rawNetinst], prefix)
			}
		}
		d.candidateMu.Unlock()
		d.TriggerRedistSync(netinst)
		return
	}

	data := r.GetData()
	if data == nil {
		d.candidateMu.Unlock()
		return
	}

	// Skip EIGRP's own routes
	if d.appId != 0 && data.GetOwnerId() == d.appId {
		delete(d.candidateRoutes[netinst], prefix)
		if rawNetinst != "" && rawNetinst != netinst {
			if _, ok := d.candidateRoutes[rawNetinst]; ok {
				delete(d.candidateRoutes[rawNetinst], prefix)
			}
		}
		d.candidateMu.Unlock()
		return
	}

	ownerName := d.getAppOwner(data.GetOwnerId())
	if strings.Contains(strings.ToLower(ownerName), "eigrp") {
		delete(d.candidateRoutes[netinst], prefix)
		if rawNetinst != "" && rawNetinst != netinst {
			if _, ok := d.candidateRoutes[rawNetinst]; ok {
				delete(d.candidateRoutes[rawNetinst], prefix)
			}
		}
		d.candidateMu.Unlock()
		return
	}

	var nhStr string
	for _, nh := range data.GetNexthops() {
		if nh.GetIpNexthop() != nil && len(nh.GetIpNexthop().GetIpAddress()) > 0 {
			nhIP := net.IP(nh.GetIpNexthop().GetIpAddress())
			if !nhIP.IsUnspecified() {
				nhStr = nhIP.String()
				break
			}
		}
	}

	routeType := ownerName
	if routeType == "" {
		routeType = "static"
	}

	cr := CandidateRoute{
		Prefix:     prefix,
		RouteType:  routeType,
		RouteOwner: ownerName,
		NextHop:    nhStr,
		AFI:        afi,
		OwnerId:    data.GetOwnerId(),
	}
	d.candidateRoutes[netinst][prefix] = cr
	if rawNetinst != "" && rawNetinst != netinst {
		if d.candidateRoutes[rawNetinst] == nil {
			d.candidateRoutes[rawNetinst] = make(map[string]CandidateRoute)
		}
		d.candidateRoutes[rawNetinst][prefix] = cr
	}
	d.candidateMu.Unlock()

	d.TriggerRedistSync(netinst)
}

func (d *EigrpDaemon) HandleBfdNotification(bfd *ndk.BfdSessionNotification) {
	if bfd == nil || bfd.Key == nil {
		return
	}
	p2p := bfd.Key.GetP2P()
	if p2p == nil {
		return
	}
	destIpBytes := p2p.GetDestinationIpAddress().GetIpAddress()
	destIp := net.IP(destIpBytes).String()
	status := bfd.GetData().GetStatus()
	log.Info().Str("peer", destIp).Str("status", status.String()).Msg("Received BFD session notification")

	statusStr := "unknown"
	switch status {
	case ndk.BfdSessionStatus_BFD_SESSION_STATUS_UP:
		statusStr = "up"
	case ndk.BfdSessionStatus_BFD_SESSION_STATUS_DOWN:
		statusStr = "down"
	case ndk.BfdSessionStatus_BFD_SESSION_STATUS_ADMIN_DOWN:
		statusStr = "admin-down"
	case ndk.BfdSessionStatus_BFD_SESSION_STATUS_INIT:
		statusStr = "init"
	}

	type nbrToClear struct {
		netinst string
		destIp  string
	}
	var toClear []nbrToClear

	d.mu.Lock()
	for _, inst := range d.instances {
		_, inNbr := inst.neighbors[destIp]
		_, inBfd := inst.bfdSessions[destIp]
		var inTemp bool
		if inst.collecting && inst.tempNeighbors != nil {
			_, inTemp = inst.tempNeighbors[destIp]
		}
		if !inNbr && !inBfd && !inTemp {
			continue
		}
		inst.bfdSessions[destIp] = statusStr
		if nbr, ok := inst.neighbors[destIp]; ok {
			nbr.BfdState = statusStr
		}
		if inst.collecting && inst.tempNeighbors != nil {
			if nbr, ok := inst.tempNeighbors[destIp]; ok {
				nbr.BfdState = statusStr
			}
		}
		if status == ndk.BfdSessionStatus_BFD_SESSION_STATUS_DOWN || status == ndk.BfdSessionStatus_BFD_SESSION_STATUS_ADMIN_DOWN {
			log.Warn().Str("neighbor", destIp).Str("netinst", inst.netinst).Msg("BFD down transition: tearing down neighbor immediately")
			toClear = append(toClear, nbrToClear{netinst: inst.netinst, destIp: destIp})
		}
	}
	d.mu.Unlock()

	for _, item := range toClear {
		cNetinst := C.CString(item.netinst)
		cNbr := C.CString(item.destIp)
		C.srlShimNeighborClear(cNetinst, cNbr)
		C.free(unsafe.Pointer(cNetinst))
		C.free(unsafe.Pointer(cNbr))
	}
	go d.CollectAndPublish(context.Background())
}
