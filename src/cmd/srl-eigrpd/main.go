package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
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
}

type NeighborInfo struct {
	IPAddress    string `json:"ip-address"`
	Interface    string `json:"interface"`
	State        string `json:"state"`
	HoldTime     uint16 `json:"hold-time"`
	Uptime       uint64 `json:"uptime"`
	SRTT         uint32 `json:"srtt-ms"`
	RTO          uint32 `json:"rto-ms"`
	BfdState     string `json:"bfd-state,omitempty"`
	RestartState string `json:"restart-state,omitempty"`
	AuthMode     string `json:"auth-mode,omitempty"`
}

type InterfaceInfo struct {
	Name          string `json:"name"`
	InterfaceName string `json:"interface-name,omitempty"`
	AdminState    string `json:"admin-state,omitempty"`
	IPAddress     string `json:"ip-address"`
	PrefixLen     uint32 `json:"prefix-length"`
	OperState     string `json:"oper-state"`
	BfdState      string `json:"bfd-state,omitempty"`
	AuthMode      string `json:"auth-mode,omitempty"`
	Passive       bool   `json:"passive"`
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
	netinst                string
	asn                    uint16
	routerId               string
	adminState             string
	operState              string
	networks               []string
	configuredInterfaces   map[string]*InterfaceConfig
	defaultIntf            *DefaultInterfaceConfig
	exportPolicy           string
	importPolicy           string
	variance               uint8
	maximumPaths           uint8
	maximumHops            uint8
	ribScale               uint8
	wideMetrics            bool
	hasV6                  bool
	gracefulRestart        *GracefulRestartConfig
	metrics                *MetricsConfig
	metricWeights          *MetricsConfig
	timers                 *TimersConfig
	authentication         *AuthConfig
	addressFamily          []AddressFamilyConfig
	restarting             bool
	bfdSessions            map[string]string
	staticNeighbors        map[string]*StaticNeighborConfig

	routes         map[string]*RouteInfo
	neighbors      map[string]*NeighborInfo
	interfaces     map[string]*InterfaceInfo
	topology       map[string]*TopologyPrefixInfo
	traffic        map[string]*TrafficInfo
	currentPfx     *TopologyPrefixInfo

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

func newEigrpInstance(netinst string) *EigrpInstance {
	return &EigrpInstance{
		netinst:                netinst,
		adminState:             "enable",
		operState:              "up",
		variance:               1,
		maximumPaths:           4,
		maximumHops:            100,
		ribScale:               128,
		wideMetrics:            true,
		configuredInterfaces:   make(map[string]*InterfaceConfig),
		staticNeighbors:        make(map[string]*StaticNeighborConfig),
		routes:                 make(map[string]*RouteInfo),
		neighbors:              make(map[string]*NeighborInfo),
		interfaces:             make(map[string]*InterfaceInfo),
		topology:               make(map[string]*TopologyPrefixInfo),
		traffic:                make(map[string]*TrafficInfo),
		tempNeighbors:          make(map[string]*NeighborInfo),
		tempInterfaces:         make(map[string]*InterfaceInfo),
		tempTopology:           make(map[string]*TopologyPrefixInfo),
		tempTraffic:            make(map[string]*TrafficInfo),
		bfdSessions:            make(map[string]string),
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
	inst.neighbors = inst.tempNeighbors
	inst.interfaces = inst.tempInterfaces
	inst.topology = inst.tempTopology
	inst.traffic = inst.tempTraffic
	inst.collecting = false
}

type EigrpDaemon struct {
	conn         *grpc.ClientConn
	sdkClient    ndk.SdkMgrServiceClient
	routeClient  ndk.SdkMgrRouteServiceClient
	nhgClient    ndk.SdkMgrNextHopGroupServiceClient
	teleClient   ndk.SdkMgrTelemetryServiceClient
	notifClient  ndk.SdkNotificationServiceClient
	appId        uint32
	streamId     uint64
	mu           sync.RWMutex
	instances    map[string]*EigrpInstance
	prevTeleKeys map[string]struct{}
	policies     map[string]*PolicyMetricConfig
}

var daemonApp *EigrpDaemon

func (d *EigrpDaemon) GetInstance(netinst string) *EigrpInstance {
	if netinst == "" {
		netinst = "default"
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.instances[netinst]
}

func (d *EigrpDaemon) GetOrCreateInstance(netinst string) *EigrpInstance {
	if netinst == "" {
		netinst = "default"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
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
	d.mu.Lock()
	delete(d.instances, netinst)
	d.mu.Unlock()
}

func (d *EigrpDaemon) CollectAndPublish(ctx context.Context) {
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

		C.srlShimInterfacesScan(cNetinst)

		d.mu.RLock()
		configuredIntfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
		for _, ic := range inst.configuredInterfaces {
			configuredIntfs = append(configuredIntfs, ic)
		}
		d.mu.RUnlock()
		for _, ic := range configuredIntfs {
			d.applyInterface(inst, ic)
		}

		C.srlShimInterfacesReport(cNetinst)
		C.srlShimNeighborsReport(cNetinst)
		C.srlShimTopologyReport(cNetinst)
		C.srlShimTrafficReport(cNetinst)
		C.free(unsafe.Pointer(cNetinst))

		d.mu.Lock()
		inst.CommitTelemetryCollection()
		d.mu.Unlock()
	}

	d.publishTelemetry(ctx)
}

func (d *EigrpDaemon) BfdSessionAddOrUpdate(netinst, peerIP, ifname, adminState string, txInterval, rxInterval uint32, mult uint8) error {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()

	if adminState == "enable" {
		cur := inst.bfdSessions[peerIP]
		if cur == "" || cur == "disabled" {
			inst.bfdSessions[peerIP] = "up"
		}
		if nbr, ok := inst.neighbors[peerIP]; ok {
			nbr.BfdState = inst.bfdSessions[peerIP]
		}
	} else {
		inst.bfdSessions[peerIP] = "disabled"
		if nbr, ok := inst.neighbors[peerIP]; ok {
			nbr.BfdState = "disabled"
		}
	}
	return nil
}

func (d *EigrpDaemon) OnNeighborReport(netinst, ip, ifname, state string, hold uint16, uptime uint64, srtt, rto uint32, bfdState, restartState, authMode string) {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()

	normIf := normalizeIfName(ifname)
	// Check whether BFD is enabled for this interface or instance
	bfdEnabled := false
	if ic, ok := inst.configuredInterfaces[ifname]; ok && ic.Bfd != nil && ic.Bfd.AdminState == "enable" {
		bfdEnabled = true
	} else if ic, ok := inst.configuredInterfaces[normIf]; ok && ic.Bfd != nil && ic.Bfd.AdminState == "enable" {
		bfdEnabled = true
	} else if inst.defaultIntf != nil && inst.defaultIntf.Bfd != nil && inst.defaultIntf.Bfd.AdminState == "enable" {
		bfdEnabled = true
	}

	if bfdEnabled {
		if sess, ok := inst.bfdSessions[ip]; ok && sess != "" && sess != "disabled" {
			bfdState = sess
			if state == "Up" && (sess == "down" || sess == "admin-down" || sess == "init") {
				inst.bfdSessions[ip] = "up"
				bfdState = "up"
			}
		} else if state == "Up" {
			inst.bfdSessions[ip] = "up"
			bfdState = "up"
		} else {
			bfdState = "init"
		}
	} else {
		bfdState = "disabled"
		inst.bfdSessions[ip] = "disabled"
	}

	// Check interface config for auth mode fallback
	if authMode == "" || authMode == "none" {
		if ic, ok := inst.configuredInterfaces[ifname]; ok && ic.Authentication != nil && ic.Authentication.Mode != "" {
			authMode = ic.Authentication.Mode
		} else if ic, ok := inst.configuredInterfaces[normIf]; ok && ic.Authentication != nil && ic.Authentication.Mode != "" {
			authMode = ic.Authentication.Mode
		} else if inst.defaultIntf != nil && inst.defaultIntf.Authentication != nil && inst.defaultIntf.Authentication.Mode != "" {
			authMode = inst.defaultIntf.Authentication.Mode
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
	if bfdState == "disabled" {
		if cur, ok := inst.bfdSessions[name]; ok {
			bfdState = cur
		} else if cur, ok := inst.bfdSessions[normIf]; ok {
			bfdState = cur
		}
	}
	authMode := "none"
	if ic, ok := inst.configuredInterfaces[name]; ok && ic.Authentication != nil && ic.Authentication.Mode != "" {
		authMode = ic.Authentication.Mode
	} else if ic, ok := inst.configuredInterfaces[normIf]; ok && ic.Authentication != nil && ic.Authentication.Mode != "" {
		authMode = ic.Authentication.Mode
	} else if inst.defaultIntf != nil && inst.defaultIntf.Authentication != nil && inst.defaultIntf.Authentication.Mode != "" {
		authMode = inst.defaultIntf.Authentication.Mode
	}

	isPassive := false
	if inst.defaultIntf != nil {
		isPassive = inst.defaultIntf.Passive
	}
	if ic, ok := inst.configuredInterfaces[name]; ok && ic.Passive != nil {
		isPassive = *ic.Passive
	} else if ic, ok := inst.configuredInterfaces[normIf]; ok && ic.Passive != nil {
		isPassive = *ic.Passive
	}

	adminState := "enable"
	if ic, ok := inst.configuredInterfaces[name]; ok && ic.AdminState != "" {
		adminState = ic.AdminState
	} else if ic, ok := inst.configuredInterfaces[normIf]; ok && ic.AdminState != "" {
		adminState = ic.AdminState
	} else if inst.defaultIntf != nil && inst.defaultIntf.AdminState != "" {
		adminState = inst.defaultIntf.AdminState
	}

	info := &InterfaceInfo{
		Name:          name,
		InterfaceName: normIf,
		AdminState:    adminState,
		IPAddress:     ipAddr,
		PrefixLen:     prefixlen,
		OperState:     operState,
		BfdState:      bfdState,
		AuthMode:      authMode,
		Passive:       isPassive,
	}
	if inst.collecting {
		inst.tempInterfaces[name] = info
	} else {
		inst.interfaces[name] = info
	}
}

func (d *EigrpDaemon) OnTopologyPrefix(netinst, prefix string, active bool, fd uint32, wideFd uint64, succCount uint32) {
	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	defer d.mu.Unlock()
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
	_ = os.Chmod(sockPath, 0666)

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
		conn:         conn,
		sdkClient:    ndk.NewSdkMgrServiceClient(conn),
		routeClient:  ndk.NewSdkMgrRouteServiceClient(conn),
		nhgClient:    ndk.NewSdkMgrNextHopGroupServiceClient(conn),
		teleClient:   ndk.NewSdkMgrTelemetryServiceClient(conn),
		notifClient:  ndk.NewSdkNotificationServiceClient(conn),
		instances:    make(map[string]*EigrpInstance),
		prevTeleKeys: make(map[string]struct{}),
		policies:     make(map[string]*PolicyMetricConfig),
	}

	daemonApp.Register(ctx)

	if err := daemonApp.InitNotificationStream(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize notification stream")
	}
	go daemonApp.RunNotificationLoop(ctx)

	daemonApp.StartIPCServer(ctx)
	go daemonApp.TelemetryWorker(ctx)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Info().Str("signal", sig.String()).Msg("Shutting down srl-eigrpd...")
	C.srlShimFinish()
	if conn != nil {
		conn.Close()
	}
	os.Exit(0)
}

func (d *EigrpDaemon) Register(ctx context.Context) {
	req := &ndk.AgentRegistrationRequest{
		WaitConfigAck: false,
	}
	resp, err := d.sdkClient.AgentRegister(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("NDK registration failed")
		return
	}
	d.appId = resp.AppId
	log.Info().Uint32("app_id", d.appId).Msg("Successfully registered with SR Linux NDK Manager")

	delReq := &ndk.TelemetryDeleteRequest{
		Keys: []*ndk.TelemetryKey{
			{JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.state"},
		},
	}
	_, _ = d.teleClient.TelemetryDelete(ctx, delReq)
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
	return nil
}

func (d *EigrpDaemon) RunNotificationLoop(ctx context.Context) {
	for {
		stream, err := d.notifClient.NotificationStream(ctx, &ndk.NotificationStreamRequest{StreamId: d.streamId})
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		log.Info().Msg("Notification stream active and listening for events")

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
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
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

	d.mu.Lock()
	for _, inst := range d.instances {
		inst.bfdSessions[destIp] = statusStr
		if nbr, ok := inst.neighbors[destIp]; ok {
			nbr.BfdState = statusStr
		}
		if status == ndk.BfdSessionStatus_BFD_SESSION_STATUS_DOWN || status == ndk.BfdSessionStatus_BFD_SESSION_STATUS_ADMIN_DOWN {
			log.Warn().Str("neighbor", destIp).Str("netinst", inst.netinst).Msg("BFD down transition: tearing down neighbor immediately")
			cNetinst := C.CString(inst.netinst)
			cNbr := C.CString(destIp)
			C.srlShimNeighborClear(cNetinst, cNbr)
			C.free(unsafe.Pointer(cNetinst))
			C.free(unsafe.Pointer(cNbr))
		}
	}
	d.mu.Unlock()
	go d.CollectAndPublish(context.Background())
}
