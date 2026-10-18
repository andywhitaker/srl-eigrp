package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

/*
#include <stdlib.h>
#include <stdbool.h>
#include "srl_cshim.h"
*/
import "C"

type BfdConfig struct {
	AdminState               string  `json:"admin-state,omitempty"`
	DesiredMinimumTxInterval *uint32 `json:"desired-minimum-tx-interval,omitempty"`
	RequiredMinimumReceive   *uint32 `json:"required-minimum-receive,omitempty"`
	DetectionMultiplier      *uint8  `json:"detection-multiplier,omitempty"`
}

type AuthConfig struct {
	AdminState        string `json:"admin-state,omitempty"`
	Mode              string `json:"mode,omitempty"`
	Keychain          string `json:"keychain,omitempty"`
	AuthenticationKey string `json:"authentication-key,omitempty"`
}

type GracefulRestartConfig struct {
	AdminState  string `json:"admin-state,omitempty"`
	RestartTime uint16 `json:"restart-time,omitempty"`
	HelperMode  *bool  `json:"helper-mode,omitempty"`
	OperState   string `json:"oper-state,omitempty"`
}

type KeychainKeyConfig struct {
	Index             uint8  `json:"index"`
	Algorithm         string `json:"algorithm,omitempty"`
	AuthenticationKey string `json:"authentication-key,omitempty"`
	AdminState        string `json:"admin-state,omitempty"`
}

type KeychainConfig struct {
	Name       string              `json:"name"`
	AdminState string              `json:"admin-state,omitempty"`
	Key        []KeychainKeyConfig `json:"key,omitempty"`
}

type SummaryAddressConfig struct {
	Prefix   string `json:"prefix"`
	Distance uint8  `json:"distance,omitempty"`
}

type StaticNeighborConfig struct {
	IPAddress string `json:"ip-address"`
	Interface string `json:"interface"`
}

type BfdStateConfig struct {
	SessionState  string `json:"session-state,omitempty"`
	RemoteAddress string `json:"remote-address,omitempty"`
}

type InterfaceAddressFamilyConfig struct {
	Name             string                 `json:"name"`
	AdminState       string                 `json:"admin-state,omitempty"`
	OperState        string                 `json:"oper-state,omitempty"`
	OperDownReason   string                 `json:"oper-down-reason,omitempty"`
	Passive          *bool                  `json:"passive,omitempty"`
	HelloInterval    *uint16                `json:"hello-interval,omitempty"`
	HoldTime         *uint16                `json:"hold-time,omitempty"`
	SplitHorizon     *bool                  `json:"split-horizon,omitempty"`
	NextHopSelf      *bool                  `json:"next-hop-self,omitempty"`
	BandwidthPercent *uint32                `json:"bandwidth-percent,omitempty"`
	SummaryAddress   []SummaryAddressConfig `json:"summary-address,omitempty"`
	Authentication   *AuthConfig            `json:"authentication,omitempty"`
	Bfd              *BfdConfig             `json:"bfd,omitempty"`
	BfdState         *BfdStateConfig        `json:"bfd-state,omitempty"`
}

type InterfaceConfig struct {
	InterfaceName    string                         `json:"interface-name"`
	AdminState       string                         `json:"admin-state,omitempty"`
	Passive          *bool                          `json:"passive,omitempty"`
	VlanID           *uint16                        `json:"vlan-id,omitempty"`
	HelloInterval    *uint16                        `json:"hello-interval,omitempty"`
	HoldTime         *uint16                        `json:"hold-time,omitempty"`
	SplitHorizon     *bool                          `json:"split-horizon,omitempty"`
	NextHopSelf      *bool                          `json:"next-hop-self,omitempty"`
	Bandwidth        *uint32                        `json:"bandwidth,omitempty"`
	BandwidthPercent *uint32                        `json:"bandwidth-percent,omitempty"`
	Delay            *uint32                        `json:"delay,omitempty"`
	SummaryAddress   []SummaryAddressConfig         `json:"summary-address,omitempty"`
	Authentication   *AuthConfig                    `json:"authentication,omitempty"`
	Bfd              *BfdConfig                     `json:"bfd,omitempty"`
	AddressFamily    []InterfaceAddressFamilyConfig `json:"address-family,omitempty"`
}

type DefaultInterfaceConfig struct {
	AdminState       string                         `json:"admin-state"`
	Passive          bool                           `json:"passive"`
	HelloInterval    uint16                         `json:"hello-interval"`
	HoldTime         uint16                         `json:"hold-time"`
	SplitHorizon     *bool                          `json:"split-horizon,omitempty"`
	NextHopSelf      *bool                          `json:"next-hop-self,omitempty"`
	Bandwidth        *uint32                        `json:"bandwidth,omitempty"`
	BandwidthPercent *uint32                        `json:"bandwidth-percent,omitempty"`
	Delay            *uint32                        `json:"delay,omitempty"`
	Authentication   *AuthConfig                    `json:"authentication,omitempty"`
	Bfd              *BfdConfig                     `json:"bfd,omitempty"`
	AddressFamily    []InterfaceAddressFamilyConfig `json:"address-family,omitempty"`
}

func (ic *InterfaceConfig) GetAfiConfig(afi string) *InterfaceAddressFamilyConfig {
	if ic == nil {
		return nil
	}
	for i := range ic.AddressFamily {
		if ic.AddressFamily[i].Name == afi {
			return &ic.AddressFamily[i]
		}
	}
	return nil
}

func (ic *InterfaceConfig) GetOrCreateAfiConfig(afi string) *InterfaceAddressFamilyConfig {
	if ic == nil {
		return nil
	}
	for i := range ic.AddressFamily {
		if ic.AddressFamily[i].Name == afi {
			return &ic.AddressFamily[i]
		}
	}
	ic.AddressFamily = append(ic.AddressFamily, InterfaceAddressFamilyConfig{Name: afi})
	return &ic.AddressFamily[len(ic.AddressFamily)-1]
}

func (ic *InterfaceConfig) IsAfiEnabled(afi string, defAdmin string) bool {
	if ic == nil {
		return defAdmin != "disable"
	}
	if ic.AdminState == "disable" {
		return false
	}
	if af := ic.GetAfiConfig(afi); af != nil && af.AdminState != "" {
		return af.AdminState != "disable"
	}
	return defAdmin != "disable"
}

func (ic *InterfaceConfig) IsAfiPassive(afi string, defPassive bool) bool {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.Passive != nil {
			return *af.Passive
		}
		if ic.Passive != nil {
			return *ic.Passive
		}
	}
	return defPassive
}

func (ic *InterfaceConfig) GetAfiHelloInterval(afi string, defIntf *DefaultInterfaceConfig) uint16 {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.HelloInterval != nil && *af.HelloInterval > 0 {
			return *af.HelloInterval
		}
		if ic.HelloInterval != nil && *ic.HelloInterval > 0 {
			return *ic.HelloInterval
		}
	}
	if defIntf != nil {
		return defIntf.GetAfiHelloInterval(afi)
	}
	return 5
}

func (ic *InterfaceConfig) GetAfiHoldTime(afi string, defIntf *DefaultInterfaceConfig) uint16 {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.HoldTime != nil && *af.HoldTime > 0 {
			return *af.HoldTime
		}
		if ic.HoldTime != nil && *ic.HoldTime > 0 {
			return *ic.HoldTime
		}
	}
	if defIntf != nil {
		return defIntf.GetAfiHoldTime(afi)
	}
	return 15
}

func (ic *InterfaceConfig) GetAfiSplitHorizon(afi string, defIntf *DefaultInterfaceConfig) bool {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.SplitHorizon != nil {
			return *af.SplitHorizon
		}
		if ic.SplitHorizon != nil {
			return *ic.SplitHorizon
		}
	}
	if defIntf != nil {
		return defIntf.GetAfiSplitHorizon(afi)
	}
	return true
}

func (ic *InterfaceConfig) GetAfiNextHopSelf(afi string, defIntf *DefaultInterfaceConfig) bool {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.NextHopSelf != nil {
			return *af.NextHopSelf
		}
		if ic.NextHopSelf != nil {
			return *ic.NextHopSelf
		}
	}
	if defIntf != nil {
		return defIntf.GetAfiNextHopSelf(afi)
	}
	return false
}

func (ic *InterfaceConfig) GetAfiBandwidthPercent(afi string, defIntf *DefaultInterfaceConfig) uint32 {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.BandwidthPercent != nil && *af.BandwidthPercent > 0 {
			if *af.BandwidthPercent != 50 {
				return *af.BandwidthPercent
			}
		}
		if ic.BandwidthPercent != nil && *ic.BandwidthPercent > 0 {
			if *ic.BandwidthPercent != 50 {
				return *ic.BandwidthPercent
			}
		}
	}
	if defIntf != nil {
		return defIntf.GetAfiBandwidthPercent(afi)
	}
	return 50
}

func (ic *InterfaceConfig) GetAfiAuthentication(afi string, defIntf *DefaultInterfaceConfig, instAuth *AuthConfig) *AuthConfig {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.Authentication != nil {
			return af.Authentication
		}
		if ic.Authentication != nil {
			return ic.Authentication
		}
	}
	if defIntf != nil {
		if auth := defIntf.GetAfiAuthentication(afi); auth != nil {
			return auth
		}
	}
	if instAuth != nil {
		return instAuth
	}
	return nil
}

func (ic *InterfaceConfig) GetAfiBfd(afi string, defIntf *DefaultInterfaceConfig) *BfdConfig {
	if ic != nil {
		if af := ic.GetAfiConfig(afi); af != nil && af.Bfd != nil {
			return af.Bfd
		}
		if ic.Bfd != nil {
			return ic.Bfd
		}
	}
	if defIntf != nil {
		return defIntf.GetAfiBfd(afi)
	}
	return nil
}

func (ic *InterfaceConfig) GetAfiSummaryAddresses(afi string) []SummaryAddressConfig {
	if ic == nil {
		return nil
	}
	if af := ic.GetAfiConfig(afi); af != nil && len(af.SummaryAddress) > 0 {
		return af.SummaryAddress
	}
	if len(ic.SummaryAddress) > 0 {
		var res []SummaryAddressConfig
		for _, sa := range ic.SummaryAddress {
			isV6 := strings.Contains(sa.Prefix, ":")
			if (afi == "ipv6-unicast" && isV6) || (afi == "ipv4-unicast" && !isV6) {
				res = append(res, sa)
			}
		}
		return res
	}
	return nil
}

func (ic *InterfaceConfig) SetAfiAdminState(afi string, state string) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.AdminState = state
	}
}

func (ic *InterfaceConfig) SetAfiPassive(afi string, passive *bool) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.Passive = passive
	}
}

func (ic *InterfaceConfig) SetAfiHelloInterval(afi string, interval *uint16) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.HelloInterval = interval
	}
}

func (ic *InterfaceConfig) SetAfiHoldTime(afi string, holdTime *uint16) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.HoldTime = holdTime
	}
}

func (ic *InterfaceConfig) SetAfiSplitHorizon(afi string, sh *bool) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.SplitHorizon = sh
	}
}

func (ic *InterfaceConfig) SetAfiNextHopSelf(afi string, nhs *bool) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.NextHopSelf = nhs
	}
}

func (ic *InterfaceConfig) SetAfiBandwidthPercent(afi string, pct *uint32) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.BandwidthPercent = pct
	}
}

func (ic *InterfaceConfig) SetAfiAuthentication(afi string, auth *AuthConfig) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.Authentication = auth
	}
}

func (ic *InterfaceConfig) SetAfiBfd(afi string, bfd *BfdConfig) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.Bfd = bfd
	}
}

func (ic *InterfaceConfig) AddOrUpdateAfiSummaryAddress(afi string, sa SummaryAddressConfig) {
	af := ic.GetOrCreateAfiConfig(afi)
	if af == nil {
		return
	}
	for i, existing := range af.SummaryAddress {
		if existing.Prefix == sa.Prefix {
			af.SummaryAddress[i] = sa
			return
		}
	}
	af.SummaryAddress = append(af.SummaryAddress, sa)
}

func (ic *InterfaceConfig) DeleteAfiSummaryAddress(afi string, prefix string) {
	af := ic.GetAfiConfig(afi)
	if af == nil {
		return
	}
	if prefix == "" {
		af.SummaryAddress = nil
		return
	}
	var updated []SummaryAddressConfig
	for _, sa := range af.SummaryAddress {
		if sa.Prefix != prefix {
			updated = append(updated, sa)
		}
	}
	af.SummaryAddress = updated
}

func (dc *DefaultInterfaceConfig) GetAfiConfig(afi string) *InterfaceAddressFamilyConfig {
	if dc == nil {
		return nil
	}
	for i := range dc.AddressFamily {
		if dc.AddressFamily[i].Name == afi {
			return &dc.AddressFamily[i]
		}
	}
	return nil
}

func (dc *DefaultInterfaceConfig) GetOrCreateAfiConfig(afi string) *InterfaceAddressFamilyConfig {
	if dc == nil {
		return nil
	}
	for i := range dc.AddressFamily {
		if dc.AddressFamily[i].Name == afi {
			return &dc.AddressFamily[i]
		}
	}
	dc.AddressFamily = append(dc.AddressFamily, InterfaceAddressFamilyConfig{Name: afi})
	return &dc.AddressFamily[len(dc.AddressFamily)-1]
}

func (dc *DefaultInterfaceConfig) IsAfiEnabled(afi string) bool {
	if dc == nil {
		return true
	}
	if dc.AdminState == "disable" {
		return false
	}
	if af := dc.GetAfiConfig(afi); af != nil && af.AdminState != "" {
		return af.AdminState != "disable"
	}
	return dc.AdminState != "disable"
}

func (dc *DefaultInterfaceConfig) IsAfiPassive(afi string) bool {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.Passive != nil {
			return *af.Passive
		}
		return dc.Passive
	}
	return false
}

func (dc *DefaultInterfaceConfig) GetAfiHelloInterval(afi string) uint16 {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.HelloInterval != nil && *af.HelloInterval > 0 {
			return *af.HelloInterval
		}
		if dc.HelloInterval > 0 {
			return dc.HelloInterval
		}
	}
	return 5
}

func (dc *DefaultInterfaceConfig) GetAfiHoldTime(afi string) uint16 {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.HoldTime != nil && *af.HoldTime > 0 {
			return *af.HoldTime
		}
		if dc.HoldTime > 0 {
			return dc.HoldTime
		}
	}
	return 15
}

func (dc *DefaultInterfaceConfig) GetAfiSplitHorizon(afi string) bool {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.SplitHorizon != nil {
			return *af.SplitHorizon
		}
		if dc.SplitHorizon != nil {
			return *dc.SplitHorizon
		}
	}
	return true
}

func (dc *DefaultInterfaceConfig) GetAfiNextHopSelf(afi string) bool {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.NextHopSelf != nil {
			return *af.NextHopSelf
		}
		if dc.NextHopSelf != nil {
			return *dc.NextHopSelf
		}
	}
	return false
}

func (dc *DefaultInterfaceConfig) GetAfiBandwidthPercent(afi string) uint32 {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.BandwidthPercent != nil && *af.BandwidthPercent > 0 {
			if *af.BandwidthPercent != 50 || dc.BandwidthPercent == nil || *dc.BandwidthPercent == 0 {
				return *af.BandwidthPercent
			}
		}
		if dc.BandwidthPercent != nil && *dc.BandwidthPercent > 0 {
			return *dc.BandwidthPercent
		}
	}
	return 50
}

func (dc *DefaultInterfaceConfig) GetAfiAuthentication(afi string) *AuthConfig {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.Authentication != nil {
			return af.Authentication
		}
		return dc.Authentication
	}
	return nil
}

func (dc *DefaultInterfaceConfig) GetAfiBfd(afi string) *BfdConfig {
	if dc != nil {
		if af := dc.GetAfiConfig(afi); af != nil && af.Bfd != nil {
			return af.Bfd
		}
		return dc.Bfd
	}
	return nil
}

func (dc *DefaultInterfaceConfig) SetAfiAdminState(afi string, state string) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.AdminState = state
	}
}

func (dc *DefaultInterfaceConfig) SetAfiPassive(afi string, passive *bool) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.Passive = passive
	}
}

func (dc *DefaultInterfaceConfig) SetAfiHelloInterval(afi string, interval *uint16) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.HelloInterval = interval
	}
}

func (dc *DefaultInterfaceConfig) SetAfiHoldTime(afi string, holdTime *uint16) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.HoldTime = holdTime
	}
}

func (dc *DefaultInterfaceConfig) SetAfiSplitHorizon(afi string, sh *bool) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.SplitHorizon = sh
	}
}

func (dc *DefaultInterfaceConfig) SetAfiNextHopSelf(afi string, nhs *bool) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.NextHopSelf = nhs
	}
}

func (dc *DefaultInterfaceConfig) SetAfiBandwidthPercent(afi string, pct *uint32) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.BandwidthPercent = pct
	}
}

func (dc *DefaultInterfaceConfig) SetAfiAuthentication(afi string, auth *AuthConfig) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.Authentication = auth
	}
}

func (dc *DefaultInterfaceConfig) SetAfiBfd(afi string, bfd *BfdConfig) {
	af := dc.GetOrCreateAfiConfig(afi)
	if af != nil {
		af.Bfd = bfd
	}
}

type TimersConfig struct {
	ActiveTime uint16 `json:"active-time"`
}

type MetricsConfig struct {
	Bandwidth          uint8  `json:"bandwidth"`
	Load               uint8  `json:"load"`
	Delay              uint8  `json:"delay"`
	Reliability        uint8  `json:"reliability"`
	Mtu                uint8  `json:"mtu"`
	ExtendedAttributes *uint8 `json:"extended-attributes,omitempty"`
	K1                 *uint8 `json:"k1,omitempty"`
	K2                 *uint8 `json:"k2,omitempty"`
	K3                 *uint8 `json:"k3,omitempty"`
	K4                 *uint8 `json:"k4,omitempty"`
	K5                 *uint8 `json:"k5,omitempty"`
	K6                 *uint8 `json:"k6,omitempty"`
	RibScale           *uint8 `json:"rib-scale,omitempty"`
}

type PolicyMetricConfig struct {
	Bandwidth   uint32 `json:"bandwidth"`
	Delay       uint32 `json:"delay"`
	Reliability uint8  `json:"reliability"`
	Load        uint8  `json:"load"`
	Mtu         uint32 `json:"mtu"`
}

type MaxPrefixConfig struct {
	Limit       uint32 `json:"limit,omitempty"`
	Threshold   uint8  `json:"threshold,omitempty"`
	WarningOnly *bool  `json:"warning-only,omitempty"`
}

type PolicyMatch struct {
	Protocol string `json:"protocol"`
}

type PolicyEigrpAction struct {
	Metric PolicyMetricConfig `json:"metric"`
}

type PolicyAction struct {
	PolicyResult string            `json:"policy-result"`
	Eigrp        PolicyEigrpAction `json:"eigrp"`
}

func (pa *PolicyAction) UnmarshalJSON(data []byte) error {
	type Alias PolicyAction
	aux := &struct {
		SrlEigrp *PolicyEigrpAction `json:"srl_nokia-eigrp:eigrp"`
		*Alias
	}{
		Alias: (*Alias)(pa),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.SrlEigrp != nil {
		if pa.Eigrp.Metric.Bandwidth == 0 && aux.SrlEigrp.Metric.Bandwidth != 0 {
			pa.Eigrp.Metric.Bandwidth = aux.SrlEigrp.Metric.Bandwidth
		}
		if pa.Eigrp.Metric.Delay == 0 && aux.SrlEigrp.Metric.Delay != 0 {
			pa.Eigrp.Metric.Delay = aux.SrlEigrp.Metric.Delay
		}
		if pa.Eigrp.Metric.Reliability == 0 && aux.SrlEigrp.Metric.Reliability != 0 {
			pa.Eigrp.Metric.Reliability = aux.SrlEigrp.Metric.Reliability
		}
		if pa.Eigrp.Metric.Load == 0 && aux.SrlEigrp.Metric.Load != 0 {
			pa.Eigrp.Metric.Load = aux.SrlEigrp.Metric.Load
		}
		if pa.Eigrp.Metric.Mtu == 0 && aux.SrlEigrp.Metric.Mtu != 0 {
			pa.Eigrp.Metric.Mtu = aux.SrlEigrp.Metric.Mtu
		}
	}
	return nil
}

type PolicyStatement struct {
	Name   string       `json:"name"`
	Match  PolicyMatch  `json:"match"`
	Action PolicyAction `json:"action"`
}

type PolicyDef struct {
	Name          string            `json:"name"`
	DefaultAction PolicyAction      `json:"default-action"`
	Statement     []PolicyStatement `json:"statement"`
}

type CandidateRoute struct {
	Prefix     string
	RouteType  string
	RouteOwner string
	NextHop    string
	AFI        string
	OwnerId    uint32
}

type AddressFamilyConfig struct {
	Name                 string              `json:"name"`
	AdminState           string              `json:"admin-state,omitempty"`
	ExportPolicy         string              `json:"export-policy,omitempty"`
	ImportPolicy         string              `json:"import-policy,omitempty"`
	Preference           uint8               `json:"preference,omitempty"`
	ExternalPreference   uint8               `json:"external-preference,omitempty"`
	TrafficShareBalanced *bool               `json:"traffic-share-balanced,omitempty"`
	AutoSummary          *bool               `json:"auto-summary,omitempty"`
	DefaultMetric        *PolicyMetricConfig `json:"default-metric,omitempty"`
	MaximumPrefix        *MaxPrefixConfig    `json:"maximum-prefix,omitempty"`
}

type EigrpConfig struct {
	AdminState           string                  `json:"admin-state"`
	AutonomousSystem     uint16                  `json:"autonomous-system"`
	RouterId             string                  `json:"router-id"`
	ExportPolicy         string                  `json:"export-policy"`
	ImportPolicy         string                  `json:"import-policy"`
	Variance             uint8                   `json:"variance"`
	MaximumPaths         uint8                   `json:"maximum-paths"`
	MaximumHops          uint8                   `json:"maximum-hops"`
	RibScale             *uint8                  `json:"rib-scale,omitempty"`
	Preference           uint8                   `json:"preference,omitempty"`
	ExternalPreference   uint8                   `json:"external-preference,omitempty"`
	WideMetrics          *bool                   `json:"wide-metrics,omitempty"`
	TrafficShareBalanced *bool                   `json:"traffic-share-balanced,omitempty"`
	AutoSummary          *bool                   `json:"auto-summary,omitempty"`
	EventLogSize         *uint32                 `json:"event-log-size,omitempty"`
	DefaultMetric        *PolicyMetricConfig     `json:"default-metric,omitempty"`
	MaximumPrefix        *MaxPrefixConfig        `json:"maximum-prefix,omitempty"`
	GracefulRestart      *GracefulRestartConfig  `json:"graceful-restart,omitempty"`
	Authentication       *AuthConfig             `json:"authentication,omitempty"`
	Timers               *TimersConfig           `json:"timers,omitempty"`
	Metrics              *MetricsConfig          `json:"metrics,omitempty"`
	MetricWeights        *MetricsConfig          `json:"metric-weights,omitempty"`
	DefaultInterface     *DefaultInterfaceConfig `json:"default-interface,omitempty"`
	Interface            []InterfaceConfig       `json:"interface,omitempty"`
	AddressFamily        []AddressFamilyConfig   `json:"address-family,omitempty"`
	Network              []string                `json:"network,omitempty"`
	StaticNeighbor       []StaticNeighborConfig  `json:"static-neighbor,omitempty"`
}

var (
	netinstRegex = regexp.MustCompile(`\.network[-_]instance\{(?:\.name==)?["']?([^}"']+)["']?\}`)
	intfRegex    = regexp.MustCompile(`\.interface\{(?:\.interface-name==|\.name==)?["']?([^}"']+)["']?\}`)
	policyRegex  = regexp.MustCompile(`\.policy\{(?:\.name==)?["']?([^}"']+)["']?\}`)
	afRegex      = regexp.MustCompile(`\.address[-_]family\{(?:\.name==)?["']?([^}"']+)["']?\}`)
)

func extractAfName(cfg *ndk.ConfigNotification) string {
	if cfg != nil && cfg.GetKey() != nil {
		for _, s := range []string{cfg.GetKey().GetJsPathWithKeys(), cfg.GetKey().GetJsPath()} {
			if s == "" {
				continue
			}
			matches := afRegex.FindStringSubmatch(s)
			if len(matches) > 1 && matches[1] != "" {
				return matches[1]
			}
		}
		keys := cfg.GetKey().GetKeys()
		for _, k := range keys {
			if k == "ipv4-unicast" || k == "ipv6-unicast" {
				return k
			}
		}
	}
	return ""
}

func extractNetinst(cfg *ndk.ConfigNotification) string {
	if cfg != nil && cfg.GetKey() != nil {
		keys := cfg.GetKey().GetKeys()
		if len(keys) > 0 && keys[0] != "" && keys[0] != "*" {
			return keys[0]
		}
		for _, s := range []string{cfg.GetKey().GetJsPathWithKeys(), cfg.GetKey().GetJsPath()} {
			if s == "" {
				continue
			}
			matches := netinstRegex.FindStringSubmatch(s)
			if len(matches) > 1 && matches[1] != "" && matches[1] != "*" {
				return matches[1]
			}
		}
	}
	return "default"
}

func extractIntfName(cfg *ndk.ConfigNotification) string {
	if cfg != nil && cfg.GetKey() != nil {
		for _, s := range []string{cfg.GetKey().GetJsPathWithKeys(), cfg.GetKey().GetJsPath()} {
			if s == "" {
				continue
			}
			matches := intfRegex.FindStringSubmatch(s)
			if len(matches) > 1 && matches[1] != "" {
				return matches[1]
			}
		}
		keys := cfg.GetKey().GetKeys()
		if len(keys) >= 2 && keys[1] != "" {
			return keys[1]
		}
	}
	return ""
}

var summaryRegex = regexp.MustCompile(`\.summary-address\{(?:\.prefix==)?["']?([^}"']+)["']?\}`)

func extractSummaryPrefix(cfg *ndk.ConfigNotification) string {
	if cfg != nil && cfg.GetKey() != nil {
		for _, s := range []string{cfg.GetKey().GetJsPathWithKeys(), cfg.GetKey().GetJsPath()} {
			if s == "" {
				continue
			}
			matches := summaryRegex.FindStringSubmatch(s)
			if len(matches) > 1 && matches[1] != "" {
				return matches[1]
			}
		}
		keys := cfg.GetKey().GetKeys()
		for _, k := range keys {
			if _, _, err := net.ParseCIDR(k); err == nil {
				return k
			}
		}
		jsPath := cfg.GetKey().GetJsPath()
		if strings.Contains(jsPath, ".address-family") && len(keys) >= 4 && keys[3] != "" {
			return keys[3]
		}
		if len(keys) >= 3 && keys[2] != "" && keys[2] != "ipv4-unicast" && keys[2] != "ipv6-unicast" {
			return keys[2]
		}
	}
	return ""
}

func extractPolicyName(cfg *ndk.ConfigNotification) string {
	if cfg != nil && cfg.GetKey() != nil {
		keys := cfg.GetKey().GetKeys()
		if len(keys) > 0 && keys[0] != "" {
			return keys[0]
		}
		for _, s := range []string{cfg.GetKey().GetJsPathWithKeys(), cfg.GetKey().GetJsPath()} {
			if s == "" {
				continue
			}
			matches := policyRegex.FindStringSubmatch(s)
			if len(matches) > 1 && matches[1] != "" {
				return matches[1]
			}
		}
	}
	return ""
}

func (d *EigrpDaemon) applyInterface(inst *EigrpInstance, ifcfg *InterfaceConfig) {
	if ifcfg == nil || ifcfg.InterfaceName == "" || inst == nil {
		return
	}
	d.mu.RLock()
	asn := inst.asn
	admin := inst.adminState
	d.mu.RUnlock()
	if asn == 0 || admin == "disable" {
		return
	}

	d.mu.RLock()
	_, exists := inst.configuredInterfaces[ifcfg.InterfaceName]
	if !exists {
		_, exists = inst.configuredInterfaces[normalizeIfName(ifcfg.InterfaceName)]
	}
	d.mu.RUnlock()
	if !exists {
		return
	}

	cNetinst := C.CString(inst.netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	cIfname := C.CString(ifcfg.InterfaceName)
	defer C.free(unsafe.Pointer(cIfname))

	defAdmin4 := "enable"
	defAdmin6 := "enable"
	defPassive4 := false
	defPassive6 := false
	if inst.defaultIntf != nil {
		if !inst.defaultIntf.IsAfiEnabled("ipv4-unicast") {
			defAdmin4 = "disable"
		}
		if !inst.defaultIntf.IsAfiEnabled("ipv6-unicast") {
			defAdmin6 = "disable"
		}
		defPassive4 = inst.defaultIntf.IsAfiPassive("ipv4-unicast")
		defPassive6 = inst.defaultIntf.IsAfiPassive("ipv6-unicast")
	}

	adminUp4 := inst.IsAfiEnabled("ipv4-unicast") && ifcfg.IsAfiEnabled("ipv4-unicast", defAdmin4)
	passive4 := ifcfg.IsAfiPassive("ipv4-unicast", defPassive4)
	hello4 := ifcfg.GetAfiHelloInterval("ipv4-unicast", inst.defaultIntf)
	hold4 := ifcfg.GetAfiHoldTime("ipv4-unicast", inst.defaultIntf)
	sh4 := ifcfg.GetAfiSplitHorizon("ipv4-unicast", inst.defaultIntf)
	nhs4 := ifcfg.GetAfiNextHopSelf("ipv4-unicast", inst.defaultIntf)

	adminUp6 := inst.IsAfiEnabled("ipv6-unicast") && ifcfg.IsAfiEnabled("ipv6-unicast", defAdmin6)
	passive6 := ifcfg.IsAfiPassive("ipv6-unicast", defPassive6)
	hello6 := ifcfg.GetAfiHelloInterval("ipv6-unicast", inst.defaultIntf)
	hold6 := ifcfg.GetAfiHoldTime("ipv6-unicast", inst.defaultIntf)
	sh6 := ifcfg.GetAfiSplitHorizon("ipv6-unicast", inst.defaultIntf)
	nhs6 := ifcfg.GetAfiNextHopSelf("ipv6-unicast", inst.defaultIntf)

	bandwidth := uint32(0)
	if ifcfg.Bandwidth != nil && *ifcfg.Bandwidth > 0 {
		bandwidth = *ifcfg.Bandwidth
	} else if inst.defaultIntf != nil && inst.defaultIntf.Bandwidth != nil {
		bandwidth = *inst.defaultIntf.Bandwidth
	}

	delay := uint32(0)
	if ifcfg.Delay != nil && *ifcfg.Delay > 0 {
		delay = *ifcfg.Delay
	} else if inst.defaultIntf != nil && inst.defaultIntf.Delay != nil {
		delay = *inst.defaultIntf.Delay
	}

	var vlanID uint16
	if ifcfg.VlanID != nil {
		vlanID = *ifcfg.VlanID
	} else {
		d.mu.RLock()
		if d.learnedVlans != nil {
			if v, ok := d.learnedVlans[ifcfg.InterfaceName]; ok && v > 0 {
				vlanID = v
			} else if v, ok := d.learnedVlans[normalizeIfName(ifcfg.InterfaceName)]; ok && v > 0 {
				vlanID = v
			}
		}
		d.mu.RUnlock()
		if vlanID > 0 {
			vlanCopy := vlanID
			ifcfg.VlanID = &vlanCopy
		}
	}
	C.srlShimInterfaceSetVlanId(cNetinst, cIfname, C.uint16_t(vlanID))

	C.srlShimInterfaceEnable(cNetinst, cIfname, C.bool(passive4), C.uint16_t(hello4), C.uint16_t(hold4), C.bool(adminUp4), C.bool(sh4), C.bool(nhs4), C.uint32_t(bandwidth), C.uint32_t(delay))
	C.srlShimInterfaceEnableV6(cNetinst, cIfname, C.bool(passive6), C.uint16_t(hello6), C.uint16_t(hold6), C.bool(adminUp6), C.bool(sh6), C.bool(nhs6), C.uint32_t(bandwidth), C.uint32_t(delay))

	C.srlShimInterfaceSetVlanId(cNetinst, cIfname, C.uint16_t(vlanID))

	// IPv4 authentication & bandwidth-percent
	cAfi4 := C.CString("ipv4-unicast")
	defer C.free(unsafe.Pointer(cAfi4))
	bwPct4 := ifcfg.GetAfiBandwidthPercent("ipv4-unicast", inst.defaultIntf)
	C.srlShimInterfaceBandwidthPercentUpdate(cNetinst, cIfname, cAfi4, C.uint32_t(bwPct4))
	auth4 := ifcfg.GetAfiAuthentication("ipv4-unicast", inst.defaultIntf, inst.authentication)
	if auth4 != nil && auth4.AdminState != "disable" && auth4.Mode != "" && auth4.Mode != "none" {
		cMode := C.CString(auth4.Mode)
		cKc := C.CString(auth4.Keychain)
		cKey := C.CString(auth4.AuthenticationKey)
		C.srlShimInterfaceAuthSetAfi(cNetinst, cIfname, cAfi4, cMode, cKc, cKey)
		C.free(unsafe.Pointer(cMode))
		C.free(unsafe.Pointer(cKc))
		C.free(unsafe.Pointer(cKey))
	} else {
		C.srlShimInterfaceAuthClearAfi(cNetinst, cIfname, cAfi4)
	}

	// IPv6 authentication & bandwidth-percent
	cAfi6 := C.CString("ipv6-unicast")
	defer C.free(unsafe.Pointer(cAfi6))
	bwPct6 := ifcfg.GetAfiBandwidthPercent("ipv6-unicast", inst.defaultIntf)
	C.srlShimInterfaceBandwidthPercentUpdate(cNetinst, cIfname, cAfi6, C.uint32_t(bwPct6))
	auth6 := ifcfg.GetAfiAuthentication("ipv6-unicast", inst.defaultIntf, inst.authentication)
	if auth6 != nil && auth6.AdminState != "disable" && auth6.Mode != "" && auth6.Mode != "none" {
		cMode := C.CString(auth6.Mode)
		cKc := C.CString(auth6.Keychain)
		cKey := C.CString(auth6.AuthenticationKey)
		C.srlShimInterfaceAuthSetAfi(cNetinst, cIfname, cAfi6, cMode, cKc, cKey)
		C.free(unsafe.Pointer(cMode))
		C.free(unsafe.Pointer(cKc))
		C.free(unsafe.Pointer(cKey))
	} else {
		C.srlShimInterfaceAuthClearAfi(cNetinst, cIfname, cAfi6)
	}

	// BFD resolution per AFI
	bfd4 := ifcfg.GetAfiBfd("ipv4-unicast", inst.defaultIntf)
	bfdAdmin4 := "disable"
	var bfdTx4, bfdRx4 uint32 = 1000000, 1000000
	var bfdMult4 uint8 = 3
	if bfd4 != nil {
		if bfd4.AdminState != "" {
			bfdAdmin4 = bfd4.AdminState
		}
		if bfd4.DesiredMinimumTxInterval != nil && *bfd4.DesiredMinimumTxInterval > 0 {
			bfdTx4 = *bfd4.DesiredMinimumTxInterval
		}
		if bfd4.RequiredMinimumReceive != nil && *bfd4.RequiredMinimumReceive > 0 {
			bfdRx4 = *bfd4.RequiredMinimumReceive
		}
		if bfd4.DetectionMultiplier != nil && *bfd4.DetectionMultiplier > 0 {
			bfdMult4 = *bfd4.DetectionMultiplier
		}
	}

	bfd6 := ifcfg.GetAfiBfd("ipv6-unicast", inst.defaultIntf)
	bfdAdmin6 := "disable"
	var bfdTx6, bfdRx6 uint32 = 1000000, 1000000
	var bfdMult6 uint8 = 3
	if bfd6 != nil {
		if bfd6.AdminState != "" {
			bfdAdmin6 = bfd6.AdminState
		}
		if bfd6.DesiredMinimumTxInterval != nil && *bfd6.DesiredMinimumTxInterval > 0 {
			bfdTx6 = *bfd6.DesiredMinimumTxInterval
		}
		if bfd6.RequiredMinimumReceive != nil && *bfd6.RequiredMinimumReceive > 0 {
			bfdRx6 = *bfd6.RequiredMinimumReceive
		}
		if bfd6.DetectionMultiplier != nil && *bfd6.DetectionMultiplier > 0 {
			bfdMult6 = *bfd6.DetectionMultiplier
		}
	}

	type nbrBfdInfo struct {
		ip   string
		isV6 bool
	}
	var matchingNbrs []nbrBfdInfo
	d.mu.RLock()
	normIf := normalizeIfName(ifcfg.InterfaceName)
	for nbrIP, nbr := range inst.neighbors {
		if normalizeIfName(nbr.Interface) == normIf {
			matchingNbrs = append(matchingNbrs, nbrBfdInfo{
				ip:   nbrIP,
				isV6: strings.Contains(nbrIP, ":"),
			})
		}
	}
	d.mu.RUnlock()

	for _, n := range matchingNbrs {
		if n.isV6 {
			_ = d.BfdSessionAddOrUpdate(inst.netinst, n.ip, ifcfg.InterfaceName, bfdAdmin6, bfdTx6, bfdRx6, bfdMult6)
		} else {
			_ = d.BfdSessionAddOrUpdate(inst.netinst, n.ip, ifcfg.InterfaceName, bfdAdmin4, bfdTx4, bfdRx4, bfdMult4)
		}
	}

	// Apply summary addresses
	sa4 := ifcfg.GetAfiSummaryAddresses("ipv4-unicast")
	for _, sa := range sa4 {
		if sa.Prefix != "" {
			cPfx := C.CString(sa.Prefix)
			dist := sa.Distance
			if dist == 0 {
				dist = 5
			}
			C.srlShimSummaryAddressAdd(cNetinst, cIfname, cPfx, C.uint8_t(dist))
			C.free(unsafe.Pointer(cPfx))
		}
	}
	sa6 := ifcfg.GetAfiSummaryAddresses("ipv6-unicast")
	for _, sa := range sa6 {
		if sa.Prefix != "" {
			cPfx := C.CString(sa.Prefix)
			dist := sa.Distance
			if dist == 0 {
				dist = 5
			}
			C.srlShimSummaryAddressAdd(cNetinst, cIfname, cPfx, C.uint8_t(dist))
			C.free(unsafe.Pointer(cPfx))
		}
	}
}

func (d *EigrpDaemon) applyStaticNeighbor(netinst string, sn *StaticNeighborConfig) {
	if sn == nil || sn.IPAddress == "" {
		return
	}
	if netinst == "" {
		netinst = "default"
	}
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	cIp := C.CString(sn.IPAddress)
	defer C.free(unsafe.Pointer(cIp))
	cIf := C.CString(sn.Interface)
	defer C.free(unsafe.Pointer(cIf))
	C.srlShimStaticNeighborAdd(cNetinst, cIp, cIf)
}

func (d *EigrpDaemon) deleteStaticNeighbor(netinst string, ip string, ifname string) {
	if ip == "" {
		return
	}
	if netinst == "" {
		netinst = "default"
	}
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	cIp := C.CString(ip)
	defer C.free(unsafe.Pointer(cIp))
	cIf := C.CString(ifname)
	defer C.free(unsafe.Pointer(cIf))
	C.srlShimStaticNeighborDel(cNetinst, cIp, cIf)
}

func (d *EigrpDaemon) applyInterfaceV6(inst *EigrpInstance, ifcfg *InterfaceConfig) {
	d.applyInterface(inst, ifcfg)
}

func (d *EigrpDaemon) applyTimers(netinst string, t *TimersConfig) {
	if t == nil {
		return
	}
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	C.srlShimActiveTimeUpdate(cNetinst, C.uint16_t(t.ActiveTime))
}

func (d *EigrpDaemon) applyMetrics(netinst string, m *MetricsConfig, ribScale uint8, wideMetrics bool) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	k1 := uint8(1)
	k2 := uint8(0)
	k3 := uint8(1)
	k4 := uint8(0)
	k5 := uint8(0)
	k6 := uint8(0)

	if m != nil {
		k1 = m.Bandwidth
		if m.K1 != nil {
			k1 = *m.K1
		} else if k1 == 0 && m.Bandwidth == 0 {
			k1 = 1
		}

		k2 = m.Load
		if m.K2 != nil {
			k2 = *m.K2
		}

		k3 = m.Delay
		if m.K3 != nil {
			k3 = *m.K3
		} else if k3 == 0 && m.Delay == 0 {
			k3 = 1
		}

		k4 = m.Reliability
		if m.K4 != nil {
			k4 = *m.K4
		}

		k5 = m.Mtu
		if m.K5 != nil {
			k5 = *m.K5
		}

		if m.ExtendedAttributes != nil {
			k6 = *m.ExtendedAttributes
		} else if m.K6 != nil {
			k6 = *m.K6
		}
	}

	if ribScale == 0 {
		ribScale = 128
	}

	C.srlShimMetricsUpdate(cNetinst, C.uint8_t(k1), C.uint8_t(k2), C.uint8_t(k3), C.uint8_t(k4), C.uint8_t(k5), C.uint8_t(k6), C.uint8_t(ribScale), C.bool(wideMetrics))
}

func (d *EigrpDaemon) applyGracefulRestart(netinst string, gr *GracefulRestartConfig) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	enabled := true
	restartTime := uint16(120)
	helperMode := true
	if gr != nil {
		if gr.AdminState == "disable" {
			enabled = false
		}
		if gr.RestartTime > 0 {
			restartTime = gr.RestartTime
		}
		if gr.HelperMode != nil {
			helperMode = *gr.HelperMode
		}
	}
	C.srlShimGracefulRestartUpdate(cNetinst, C.bool(enabled), C.uint16_t(restartTime), C.bool(helperMode))
}

func (d *EigrpDaemon) applyInstanceFeatures(inst *EigrpInstance) {
	if inst == nil {
		return
	}
	d.mu.RLock()
	netinst := inst.netinst
	evSize := inst.eventLogSize
	if evSize == 0 {
		evSize = 500
	}
	d.mu.RUnlock()

	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	C.srlShimEventLogSizeUpdate(cNetinst, C.uint32_t(evSize))

	for _, afName := range []string{"ipv4-unicast", "ipv6-unicast"} {
		d.mu.RLock()
		tsb := inst.GetAfiTrafficShareBalanced(afName)
		as := inst.GetAfiAutoSummary(afName)
		dm := inst.GetAfiDefaultMetric(afName)
		mp := inst.GetAfiMaximumPrefix(afName)
		d.mu.RUnlock()

		cAf := C.CString(afName)
		C.srlShimTrafficShareBalancedUpdate(cNetinst, cAf, C.bool(tsb))
		C.srlShimAutoSummaryUpdate(cNetinst, cAf, C.bool(as))

		if dm != nil && (dm.Bandwidth > 0 || dm.Delay > 0 || dm.Reliability > 0 || dm.Load > 0 || dm.Mtu > 0) {
			mCopy := *dm
			applyMetricDefaults(&mCopy)
			C.srlShimDefaultMetricUpdate(cNetinst, cAf, C.uint32_t(mCopy.Bandwidth), C.uint32_t(mCopy.Delay), C.uint8_t(mCopy.Reliability), C.uint8_t(mCopy.Load), C.uint32_t(mCopy.Mtu))
		} else {
			C.srlShimDefaultMetricUpdate(cNetinst, cAf, 0, 0, 0, 0, 0)
		}

		if mp != nil && mp.Limit > 0 {
			thresh := mp.Threshold
			if thresh == 0 {
				thresh = 75
			}
			warnOnly := false
			if mp.WarningOnly != nil {
				warnOnly = *mp.WarningOnly
			}
			C.srlShimMaxPrefixUpdate(cNetinst, cAf, C.uint32_t(mp.Limit), C.uint8_t(thresh), C.bool(warnOnly))
		} else {
			C.srlShimMaxPrefixUpdate(cNetinst, cAf, 0, 75, false)
		}
		C.free(unsafe.Pointer(cAf))
	}
}

func (d *EigrpDaemon) reapplyInstanceRuntimeConfig(inst *EigrpInstance) {
	if inst == nil {
		return
	}
	d.mu.RLock()
	netinst := inst.netinst
	asn := inst.asn
	admin := inst.adminState
	scale := inst.ribScale
	metrics := inst.metrics
	wm := inst.wideMetrics
	gr := inst.gracefulRestart
	varVar := inst.variance
	maxPaths := inst.maximumPaths
	maxHops := inst.maximumHops
	timers := inst.timers
	intDist := inst.preference
	extDist := inst.externalPreference
	afs := make([]AddressFamilyConfig, len(inst.addressFamily))
	copy(afs, inst.addressFamily)
	expPol := inst.exportPolicy
	var staticNbrs []*StaticNeighborConfig
	for _, sn := range inst.staticNeighbors {
		staticNbrs = append(staticNbrs, sn)
	}
	allIntfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
	for _, ic := range inst.configuredInterfaces {
		allIntfs = append(allIntfs, ic)
	}
	d.mu.RUnlock()

	if asn == 0 || admin == "disable" {
		return
	}
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	C.srl_set_rib_scale(cNetinst, C.uint8_t(scale))
	d.applyMetrics(netinst, metrics, scale, wm)
	d.applyGracefulRestart(netinst, gr)
	d.applyInstanceFeatures(inst)
	for _, sn := range staticNbrs {
		d.applyStaticNeighbor(netinst, sn)
	}
	for _, ic := range allIntfs {
		d.applyInterface(inst, ic)
	}
	d.applyRedistribute(netinst, expPol)
	if varVar == 0 {
		varVar = 1
	}
	C.srlShimVarianceUpdate(cNetinst, C.uint8_t(varVar))
	if maxPaths == 0 {
		maxPaths = 4
	}
	C.srlShimMaxPathsUpdate(cNetinst, C.uint8_t(maxPaths))
	if maxHops == 0 {
		maxHops = 100
	}
	C.srlShimMaxHopsUpdate(cNetinst, C.uint8_t(maxHops))
	if timers != nil {
		d.applyTimers(netinst, timers)
	}
	if intDist == 0 {
		intDist = 90
	}
	if extDist == 0 {
		extDist = 170
	}
	C.srlShimDistanceUpdate(cNetinst, C.uint8_t(intDist), C.uint8_t(extDist))
	for _, af := range afs {
		afInt := af.Preference
		if afInt == 0 {
			afInt = intDist
		}
		afExt := af.ExternalPreference
		if afExt == 0 {
			afExt = extDist
		}
		cAfName := C.CString(af.Name)
		C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(afInt), C.uint8_t(afExt))
		C.free(unsafe.Pointer(cAfName))
	}
	d.TriggerRedistSync(netinst)
}

func (d *EigrpDaemon) HandleKeychainNotification(cfg *ndk.ConfigNotification) {
	op := cfg.GetOp()
	jsonStr := cfg.GetData().GetJson()
	jsPath := cfg.GetKey().GetJsPath()
	log.Info().Str("js_path", jsPath).Str("op", op.String()).Str("json", jsonStr).Msg("Handling system keychain notification")

	var kc KeychainConfig
	if err := json.Unmarshal([]byte(jsonStr), &kc); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal keychain config")
		return
	}
	if kc.Name == "" {
		re := regexp.MustCompile(`\.keychain\{(?:\.name==)?["']?([^}"']+)["']?\}`)
		if m := re.FindStringSubmatch(cfg.GetKey().GetJsPathWithKeys()); len(m) > 1 {
			kc.Name = m[1]
		}
	}
	if kc.Name == "" {
		return
	}

	cName := C.CString(kc.Name)
	defer C.free(unsafe.Pointer(cName))

	if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE || kc.AdminState == "disable" {
		C.srlShimKeychainDel(cName)
		log.Info().Str("keychain", kc.Name).Msg("Removed keychain from shim")
		return
	}

	if len(kc.Key) == 0 {
		var singleKey KeychainKeyConfig
		if err := json.Unmarshal([]byte(jsonStr), &singleKey); err == nil {
			if singleKey.Index == 0 {
				reKey := regexp.MustCompile(`\.key\{(?:\.index==)?(\d+)\}`)
				if m := reKey.FindStringSubmatch(cfg.GetKey().GetJsPathWithKeys()); len(m) > 1 {
					if idx, err := strconv.Atoi(m[1]); err == nil {
						singleKey.Index = uint8(idx)
					}
				}
			}
			if singleKey.AuthenticationKey != "" || singleKey.Index != 0 {
				kc.Key = append(kc.Key, singleKey)
			}
		}
	}

	for _, k := range kc.Key {
		if k.AdminState != "disable" && k.AuthenticationKey != "" {
			cKey := C.CString(k.AuthenticationKey)
			cAlgo := C.CString(k.Algorithm)
			C.srlShimKeychainAdd(cName, C.uint32_t(k.Index), cKey, cAlgo)
			C.free(unsafe.Pointer(cKey))
			C.free(unsafe.Pointer(cAlgo))
			log.Info().Str("keychain", kc.Name).Uint8("index", k.Index).Msg("Configured key in shim keychain")
		}
	}
}

func (d *EigrpDaemon) applyRedistribute(netinst string, policyName string) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	if policyName == "" {
		C.srlShimRedistributeUpdate(cNetinst, nil, 0, 0, 0, 0, 0)
		d.TriggerRedistSync(netinst)
		return
	}

	cPName := C.CString(policyName)
	defer C.free(unsafe.Pointer(cPName))

	bw := uint32(100000)
	delay := uint32(100)
	rel := uint8(255)
	load := uint8(1)
	mtu := uint32(1500)

	d.mu.RLock()
	if inst, ok := d.instances[netinst]; ok && inst != nil && inst.defaultMetric != nil {
		if inst.defaultMetric.Bandwidth > 0 {
			bw = inst.defaultMetric.Bandwidth
		}
		if inst.defaultMetric.Delay > 0 {
			delay = inst.defaultMetric.Delay
		}
		if inst.defaultMetric.Reliability > 0 {
			rel = inst.defaultMetric.Reliability
		}
		if inst.defaultMetric.Load > 0 {
			load = inst.defaultMetric.Load
		}
		if inst.defaultMetric.Mtu > 0 {
			mtu = inst.defaultMetric.Mtu
		}
	}
	if pol, exists := d.policies[policyName]; exists && pol != nil {
		if pol.Bandwidth > 0 {
			bw = pol.Bandwidth
		}
		if pol.Delay > 0 {
			delay = pol.Delay
		}
		if pol.Reliability > 0 {
			rel = pol.Reliability
		}
		if pol.Load > 0 {
			load = pol.Load
		}
		if pol.Mtu > 0 {
			mtu = pol.Mtu
		}
	}
	d.mu.RUnlock()

	C.srlShimRedistributeUpdate(cNetinst, cPName, C.uint32_t(bw), C.uint32_t(delay), C.uint8_t(rel), C.uint8_t(load), C.uint32_t(mtu))
	d.TriggerRedistSync(netinst)
}

func (d *EigrpDaemon) HandleConfigNotification(cfg *ndk.ConfigNotification) {
	jsonStr := cfg.GetData().GetJson()
	jsPath := cfg.GetKey().GetJsPath()
	jsPathKeys := cfg.GetKey().GetJsPathWithKeys()
	op := cfg.GetOp()

	log.Info().
		Str("js_path", jsPath).
		Str("js_path_keys", jsPathKeys).
		Str("op", op.String()).
		Str("json", jsonStr).
		Msg("Processing Config Notification")

	// 0. Handle System Keychain notifications
	if strings.Contains(jsPath, ".keychain") || strings.Contains(jsPath, ".authentication.keychain") {
		d.HandleKeychainNotification(cfg)
		return
	}

	// 1. Handle Routing Policy notifications
	if strings.Contains(jsPath, ".routing-policy") {
		policyName := extractPolicyName(cfg)
		d.mu.Lock()
		if policyName != "" {
			delete(d.policyDefs, policyName)
			if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
				delete(d.policies, policyName)
			}
		} else {
			d.policyDefs = make(map[string]*PolicyDef)
		}
		d.mu.Unlock()

		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			log.Info().Str("policy", policyName).Msg("Removed routing-policy statement or policy")
			d.mu.RLock()
			for ni, inst := range d.instances {
				if policyName == "" || inst.exportPolicy == policyName || inst.GetAfiExportPolicy("ipv4-unicast") == policyName || inst.GetAfiExportPolicy("ipv6-unicast") == policyName {
					d.TriggerRedistSync(ni)
				}
			}
			d.mu.RUnlock()
			return
		}

		var polWrapper struct {
			Metric PolicyMetricConfig `json:"metric"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &polWrapper); err == nil && (polWrapper.Metric.Bandwidth > 0 || polWrapper.Metric.Delay > 0) {
			metric := polWrapper.Metric
			if metric.Bandwidth == 0 {
				metric.Bandwidth = 100000
			}
			if metric.Delay == 0 {
				metric.Delay = 100
			}
			if metric.Reliability == 0 {
				metric.Reliability = 255
			}
			if metric.Load == 0 {
				metric.Load = 1
			}
			if metric.Mtu == 0 {
				metric.Mtu = 1500
			}

			d.mu.Lock()
			d.policies[policyName] = &metric
			d.mu.Unlock()
			log.Info().Str("policy", policyName).Interface("metrics", metric).Msg("Learned routing-policy EIGRP metrics")

			// If active export policy matches any instance, update redistribution
			d.mu.RLock()
			var affectedInstances []string
			for ni, inst := range d.instances {
				if inst.exportPolicy == policyName || inst.GetAfiExportPolicy("ipv4-unicast") == policyName || inst.GetAfiExportPolicy("ipv6-unicast") == policyName {
					affectedInstances = append(affectedInstances, ni)
				}
			}
			d.mu.RUnlock()
			for _, ni := range affectedInstances {
				d.applyRedistribute(ni, policyName)
			}
		} else {
			d.mu.RLock()
			for ni, inst := range d.instances {
				if policyName == "" || inst.exportPolicy == policyName || inst.GetAfiExportPolicy("ipv4-unicast") == policyName || inst.GetAfiExportPolicy("ipv6-unicast") == policyName {
					d.TriggerRedistSync(ni)
				}
			}
			d.mu.RUnlock()
		}
		return
	}

	// 2. Handle Commit End
	if strings.Contains(jsPath, ".commit.end") {
		d.mu.Lock()
		d.policyDefs = make(map[string]*PolicyDef)
		d.mu.Unlock()
		d.mu.RLock()
		for ni, inst := range d.instances {
			if inst != nil && inst.adminState != "disable" && inst.asn > 0 {
				v4Policy := inst.GetAfiExportPolicy("ipv4-unicast")
				v6Policy := inst.GetAfiExportPolicy("ipv6-unicast")
				if v4Policy != "" || v6Policy != "" || len(inst.redistributedRoutes) > 0 {
					d.TriggerRedistSync(ni)
				}
			}
		}
		d.mu.RUnlock()
		return
	}

	if !strings.Contains(jsPath, ".protocols.eigrp") {
		// Handle SR Linux subinterface VLAN configuration
		// e.g. .interface{.name=="ethernet-1/1"}.subinterface{.index==1}...
		if strings.Contains(jsPath, ".interface") && strings.Contains(jsPath, ".subinterface") {
			subifRegex := regexp.MustCompile(`\.interface\{(?:\.name==)?["']?([^}"']+)["']?\}\.subinterface\{(?:\.index==)?["']?([^}"']+)["']?\}`)
			var baseDev, subIdx string
			for _, s := range []string{jsPathKeys, jsPath} {
				matches := subifRegex.FindStringSubmatch(s)
				if len(matches) > 2 {
					baseDev = matches[1]
					subIdx = matches[2]
					break
				}
			}
			if (baseDev == "" || subIdx == "") && cfg.GetKey() != nil {
				keys := cfg.GetKey().GetKeys()
				if len(keys) >= 2 && keys[0] != "" && keys[1] != "" {
					baseDev = keys[0]
					subIdx = keys[1]
				}
			}
			if baseDev != "" && subIdx != "" {
				fullIntfName := baseDev + "." + subIdx
				normIntf := normalizeIfName(fullIntfName)

				var vlanData struct {
					VlanID  *uint16 `json:"vlan-id"`
					EncapID *uint16 `json:"encap-id"`
					Vlan    struct {
						VlanID  *uint16 `json:"vlan-id"`
						EncapID *uint16 `json:"encap-id"`
						Encap   struct {
							SingleTagged struct {
								VlanID  *uint16 `json:"vlan-id"`
								EncapID *uint16 `json:"encap-id"`
							} `json:"single-tagged"`
						} `json:"encap"`
					} `json:"vlan"`
					Encap struct {
						SingleTagged struct {
							VlanID  *uint16 `json:"vlan-id"`
							EncapID *uint16 `json:"encap-id"`
						} `json:"single-tagged"`
					} `json:"encap"`
				}
				var learnedVlan uint16
				if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE && jsonStr != "" {
					if err := json.Unmarshal([]byte(jsonStr), &vlanData); err == nil {
						if vlanData.VlanID != nil {
							learnedVlan = *vlanData.VlanID
						} else if vlanData.EncapID != nil {
							learnedVlan = *vlanData.EncapID
						} else if vlanData.Vlan.VlanID != nil {
							learnedVlan = *vlanData.Vlan.VlanID
						} else if vlanData.Vlan.EncapID != nil {
							learnedVlan = *vlanData.Vlan.EncapID
						} else if vlanData.Vlan.Encap.SingleTagged.VlanID != nil {
							learnedVlan = *vlanData.Vlan.Encap.SingleTagged.VlanID
						} else if vlanData.Vlan.Encap.SingleTagged.EncapID != nil {
							learnedVlan = *vlanData.Vlan.Encap.SingleTagged.EncapID
						} else if vlanData.Encap.SingleTagged.VlanID != nil {
							learnedVlan = *vlanData.Encap.SingleTagged.VlanID
						} else if vlanData.Encap.SingleTagged.EncapID != nil {
							learnedVlan = *vlanData.Encap.SingleTagged.EncapID
						}
					}
				}
				isVlanOrSubifPath := strings.Contains(jsPath, ".vlan") || strings.Contains(jsPath, ".encap") ||
					strings.HasSuffix(jsPath, ".subinterface") ||
					(!strings.Contains(jsPath, ".ipv4") && !strings.Contains(jsPath, ".ipv6"))
				if learnedVlan > 0 {
					d.mu.Lock()
					if d.learnedVlans == nil {
						d.learnedVlans = make(map[string]uint16)
					}
					d.learnedVlans[fullIntfName] = learnedVlan
					d.learnedVlans[normIntf] = learnedVlan
					for _, inst := range d.instances {
						if ic, ok := inst.configuredInterfaces[fullIntfName]; ok {
							ic.VlanID = &learnedVlan
						} else if ic, ok := inst.configuredInterfaces[normIntf]; ok {
							ic.VlanID = &learnedVlan
						}
					}
					instanceNames := make([]string, 0, len(d.instances))
					for ni := range d.instances {
						instanceNames = append(instanceNames, ni)
					}
					if len(instanceNames) == 0 {
						instanceNames = append(instanceNames, "default")
					}
					d.mu.Unlock()

					cIntf := C.CString(fullIntfName)
					cNorm := C.CString(normIntf)
					for _, ni := range instanceNames {
						cNi := C.CString(ni)
						C.srlShimInterfaceSetVlanId(cNi, cIntf, C.uint16_t(learnedVlan))
						C.srlShimInterfaceSetVlanId(cNi, cNorm, C.uint16_t(learnedVlan))
						C.free(unsafe.Pointer(cNi))
					}
					C.free(unsafe.Pointer(cIntf))
					C.free(unsafe.Pointer(cNorm))
					log.Info().Str("interface", fullIntfName).Uint16("vlan_id", learnedVlan).Msg("Learned explicit subinterface VLAN ID from configuration")
				} else if isVlanOrSubifPath {
					d.mu.Lock()
					hadVlan := false
					if d.learnedVlans != nil {
						if _, ok := d.learnedVlans[fullIntfName]; ok {
							delete(d.learnedVlans, fullIntfName)
							hadVlan = true
						}
						if _, ok := d.learnedVlans[normIntf]; ok {
							delete(d.learnedVlans, normIntf)
							hadVlan = true
						}
					}
					for _, inst := range d.instances {
						if ic, ok := inst.configuredInterfaces[fullIntfName]; ok && ic.VlanID != nil {
							ic.VlanID = nil
							hadVlan = true
						} else if ic, ok := inst.configuredInterfaces[normIntf]; ok && ic.VlanID != nil {
							ic.VlanID = nil
							hadVlan = true
						}
					}
					instanceNames := make([]string, 0, len(d.instances))
					for ni := range d.instances {
						instanceNames = append(instanceNames, ni)
					}
					if len(instanceNames) == 0 {
						instanceNames = append(instanceNames, "default")
					}
					d.mu.Unlock()

					if hadVlan || op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
						cIntf := C.CString(fullIntfName)
						cNorm := C.CString(normIntf)
						for _, ni := range instanceNames {
							cNi := C.CString(ni)
							C.srlShimInterfaceSetVlanId(cNi, cIntf, 0)
							C.srlShimInterfaceSetVlanId(cNi, cNorm, 0)
							C.free(unsafe.Pointer(cNi))
						}
						C.free(unsafe.Pointer(cIntf))
						C.free(unsafe.Pointer(cNorm))
						log.Info().Str("interface", fullIntfName).Msg("Cleared subinterface VLAN ID from configuration")
					}
				}
			}
		} else if strings.Contains(jsPath, ".interface") && (strings.Contains(jsPath, "vlan-tagging") || strings.Contains(jsPath, "vlan_tagging") || strings.Contains(jsonStr, "\"vlan-tagging\":false") || strings.Contains(jsonStr, "\"vlan-tagging\": false")) {
			if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE || strings.Contains(jsonStr, "false") {
				ifRegex := regexp.MustCompile(`\.interface\{(?:\.name==)?["']?([^}"']+)["']?\}`)
				var baseDev string
				for _, s := range []string{jsPathKeys, jsPath} {
					if m := ifRegex.FindStringSubmatch(s); len(m) > 1 {
						baseDev = m[1]
						break
					}
				}
				if baseDev == "" && cfg.GetKey() != nil {
					if keys := cfg.GetKey().GetKeys(); len(keys) >= 1 {
						baseDev = keys[0]
					}
				}
				if baseDev != "" {
					sub0 := baseDev + ".0"
					norm0 := normalizeIfName(sub0)
					d.mu.Lock()
					if d.learnedVlans != nil {
						delete(d.learnedVlans, sub0)
						delete(d.learnedVlans, norm0)
					}
					for _, inst := range d.instances {
						if ic, ok := inst.configuredInterfaces[sub0]; ok && ic.VlanID != nil {
							ic.VlanID = nil
						}
						if ic, ok := inst.configuredInterfaces[norm0]; ok && ic.VlanID != nil {
							ic.VlanID = nil
						}
					}
					instanceNames := make([]string, 0, len(d.instances))
					for ni := range d.instances {
						instanceNames = append(instanceNames, ni)
					}
					if len(instanceNames) == 0 {
						instanceNames = append(instanceNames, "default")
					}
					d.mu.Unlock()

					cIntf := C.CString(sub0)
					cNorm := C.CString(norm0)
					for _, ni := range instanceNames {
						cNi := C.CString(ni)
						C.srlShimInterfaceSetVlanId(cNi, cIntf, 0)
						C.srlShimInterfaceSetVlanId(cNi, cNorm, 0)
						C.free(unsafe.Pointer(cNi))
					}
					C.free(unsafe.Pointer(cIntf))
					C.free(unsafe.Pointer(cNorm))
					log.Info().Str("interface", sub0).Msg("Cleared subinterface .0 VLAN ID due to parent vlan-tagging disable")
				}
			}
		}

		// Check if this is a DELETE of the entire network-instance (VRF deletion)
		cleanPath := strings.TrimPrefix(strings.TrimPrefix(jsPath, ".network_instance"), ".network-instance")
		if idx := strings.Index(cleanPath, "}"); idx != -1 && strings.HasPrefix(cleanPath, "{") {
			cleanPath = cleanPath[idx+1:]
		}
		isNetinstSelf := (cleanPath == "") && (strings.HasPrefix(jsPath, ".network_instance") || strings.HasPrefix(jsPath, ".network-instance"))

		if isNetinstSelf && op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			netinst := ""
			if cfg != nil && cfg.GetKey() != nil {
				keys := cfg.GetKey().GetKeys()
				if len(keys) > 0 && keys[0] != "" && keys[0] != "*" {
					netinst = keys[0]
				}
			}
			if netinst == "" {
				for _, s := range []string{jsPathKeys, jsPath} {
					if s == "" {
						continue
					}
					matches := netinstRegex.FindStringSubmatch(s)
					if len(matches) > 1 && matches[1] != "" && matches[1] != "*" {
						netinst = matches[1]
						break
					}
					if start := strings.Index(s, `name=="`); start != -1 {
						sub := s[start+7:]
						if end := strings.Index(sub, `"`); end != -1 {
							netinst = sub[:end]
							break
						}
					}
				}
			}
			if netinst == "" {
				netinst = extractNetinst(cfg)
			}
			if netinst != "" && d.GetInstance(netinst) != nil {
				log.Info().Str("netinst", netinst).Msg("Deleting EIGRP protocol instance due to network-instance deletion")
				inst := d.GetInstance(netinst)
				asn := uint16(0)
				if inst != nil {
					d.mu.RLock()
					asn = inst.asn
					d.mu.RUnlock()
				}
				cNetinst := C.CString(netinst)
				C.srlShimInstanceDelete(cNetinst)
				C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(asn))
				C.free(unsafe.Pointer(cNetinst))
				d.WithdrawAfRoutes(netinst, "ipv4-unicast")
				d.WithdrawAfRoutes(netinst, "ipv6-unicast")
				d.withdrawAllRedistributed(netinst)
				d.DeleteInstance(netinst)
				go d.CollectAndPublish(context.Background())
			}
		}
		return
	}

	netinst := extractNetinst(cfg)

	// Check if this is a DELETE of the entire EIGRP protocol on this network-instance
	if strings.HasSuffix(jsPath, ".protocols.eigrp") && op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
		log.Info().Str("netinst", netinst).Msg("Deleting EIGRP protocol instance")
		inst := d.GetInstance(netinst)
		asn := uint16(0)
		if inst != nil {
			d.mu.RLock()
			asn = inst.asn
			d.mu.RUnlock()
		}
		cNetinst := C.CString(netinst)
		C.srlShimInstanceDelete(cNetinst)
		C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(asn))
		C.free(unsafe.Pointer(cNetinst))
		d.WithdrawAfRoutes(netinst, "ipv4-unicast")
		d.WithdrawAfRoutes(netinst, "ipv6-unicast")
		d.withdrawAllRedistributed(netinst)
		d.DeleteInstance(netinst)
		go d.CollectAndPublish(context.Background())
		return
	}

	// 1a. Handle sub-path protocol admin-state notification
	if strings.Contains(jsPath, ".protocols.eigrp.admin-state") {
		inst := d.GetOrCreateInstance(netinst)
		cNetinst := C.CString(netinst)
		defer C.free(unsafe.Pointer(cNetinst))

		var adminStr string
		var wrapper struct {
			AdminState string `json:"admin-state"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil && wrapper.AdminState != "" {
			adminStr = wrapper.AdminState
		} else if err := json.Unmarshal([]byte(jsonStr), &adminStr); err != nil {
			if strings.Contains(jsonStr, "disable") {
				adminStr = "disable"
			} else {
				adminStr = "enable"
			}
		}

		d.mu.Lock()
		inst.adminState = adminStr
		if adminStr == "disable" {
			inst.operState = "down"
			inst.routes = make(map[string]*RouteInfo)
			inst.neighbors = make(map[string]*NeighborInfo)
			inst.topology = make(map[string]*TopologyPrefixInfo)
			inst.interfaces = make(map[string]*InterfaceInfo)
			inst.traffic = make(map[string]*TrafficInfo)
		} else {
			inst.operState = "up"
		}
		d.mu.Unlock()

		if adminStr == "disable" {
			C.srlShimInstanceDelete(cNetinst)
			C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
			d.WithdrawAfRoutes(netinst, "ipv4-unicast")
			d.WithdrawAfRoutes(netinst, "ipv6-unicast")
			d.withdrawAllRedistributed(netinst)
			log.Info().Str("netinst", netinst).Msg("EIGRP instance disabled via admin-state sub-path")
		} else if inst.asn > 0 {
			cRouterId := C.CString(inst.routerId)
			if inst.IsAfiEnabled("ipv4-unicast") {
				C.srlShimInstanceCreate(cNetinst, C.uint16_t(inst.asn), cRouterId)
			}
			if inst.IsAfiEnabled("ipv6-unicast") {
				C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
			}
			C.free(unsafe.Pointer(cRouterId))
			d.reapplyInstanceRuntimeConfig(inst)
			log.Info().Str("netinst", netinst).Msg("EIGRP instance enabled via admin-state sub-path")
		}
		go d.CollectAndPublish(context.Background())
		return
	}

	// 1a2. Handle sub-path export-policy notification
	if strings.Contains(jsPath, ".protocols.eigrp.export-policy") {
		inst := d.GetOrCreateInstance(netinst)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			inst.exportPolicy = ""
			d.mu.Unlock()
			d.applyRedistribute(netinst, "")
		} else {
			var polName string
			_ = json.Unmarshal([]byte(jsonStr), &polName)
			if polName == "" {
				var wrap struct {
					ExportPolicy string `json:"export-policy"`
				}
				_ = json.Unmarshal([]byte(jsonStr), &wrap)
				polName = wrap.ExportPolicy
			}
			d.mu.Lock()
			inst.exportPolicy = polName
			d.mu.Unlock()
			d.applyRedistribute(netinst, polName)
		}
		go d.CollectAndPublish(context.Background())
		return
	}

	// 1b. Handle sub-path static-neighbor notification
	if strings.Contains(jsPath, ".protocols.eigrp.static-neighbor") {
		inst := d.GetOrCreateInstance(netinst)
		var snIP string
		if m := regexp.MustCompile(`\.static-neighbor\{(?:\.ip-address==)?["']?([^}"']+)["']?\}`).FindStringSubmatch(jsPathKeys); len(m) > 1 {
			snIP = m[1]
		}
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			var prevIf string
			d.mu.Lock()
			if snIP != "" {
				if prev := inst.staticNeighbors[snIP]; prev != nil {
					prevIf = prev.Interface
				}
				delete(inst.staticNeighbors, snIP)
			} else {
				for _, sn := range inst.staticNeighbors {
					d.deleteStaticNeighbor(netinst, sn.IPAddress, sn.Interface)
				}
				inst.staticNeighbors = make(map[string]*StaticNeighborConfig)
			}
			d.mu.Unlock()
			if snIP != "" {
				d.deleteStaticNeighbor(netinst, snIP, prevIf)
			}
			log.Info().Str("netinst", netinst).Str("ip", snIP).Msg("Deleted static-neighbor via sub-path")
			go d.CollectAndPublish(context.Background())
			return
		}
		var sn StaticNeighborConfig
		if err := json.Unmarshal([]byte(jsonStr), &sn); err == nil {
			if sn.IPAddress == "" && snIP != "" {
				sn.IPAddress = snIP
			}
			if sn.IPAddress != "" {
				d.mu.Lock()
				inst.staticNeighbors[sn.IPAddress] = &sn
				d.mu.Unlock()
				d.applyStaticNeighbor(netinst, &sn)
				log.Info().Str("netinst", netinst).Interface("static_neighbor", sn).Msg("Updated static-neighbor via sub-path")
				go d.CollectAndPublish(context.Background())
			}
		}
		return
	}

	// 2a. Handle sub-path default-interface address-family notification
	if strings.Contains(jsPath, ".protocols.eigrp.default-interface") && strings.Contains(jsPath, ".address-family") {
		afName := extractAfName(cfg)
		if afName == "" {
			return
		}
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		if inst.defaultIntf == nil {
			inst.defaultIntf = &DefaultInterfaceConfig{AdminState: "enable"}
		}
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if strings.Contains(jsPath, ".passive") {
				inst.defaultIntf.SetAfiPassive(afName, nil)
			} else if strings.Contains(jsPath, ".hello-interval") {
				inst.defaultIntf.SetAfiHelloInterval(afName, nil)
			} else if strings.Contains(jsPath, ".hold-time") {
				inst.defaultIntf.SetAfiHoldTime(afName, nil)
			} else if strings.Contains(jsPath, ".split-horizon") {
				inst.defaultIntf.SetAfiSplitHorizon(afName, nil)
			} else if strings.Contains(jsPath, ".next-hop-self") {
				inst.defaultIntf.SetAfiNextHopSelf(afName, nil)
			} else if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
				inst.defaultIntf.SetAfiBandwidthPercent(afName, nil)
			} else if strings.Contains(jsPath, ".authentication") {
				inst.defaultIntf.SetAfiAuthentication(afName, nil)
			} else if strings.Contains(jsPath, ".bfd") {
				inst.defaultIntf.SetAfiBfd(afName, nil)
			} else if strings.Contains(jsPath, ".admin-state") {
				inst.defaultIntf.SetAfiAdminState(afName, "")
			} else {
				var updatedAF []InterfaceAddressFamilyConfig
				for _, af := range inst.defaultIntf.AddressFamily {
					if af.Name != afName {
						updatedAF = append(updatedAF, af)
					}
				}
				inst.defaultIntf.AddressFamily = updatedAF
			}
			intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
			for _, ic := range inst.configuredInterfaces {
				intfs = append(intfs, ic)
			}
			d.mu.Unlock()
			for _, ic := range intfs {
				d.applyInterface(inst, ic)
			}
			log.Info().Str("netinst", netinst).Str("af", afName).Msg("Deleted default-interface address-family and refreshed interfaces")
			go d.CollectAndPublish(context.Background())
			return
		}

		var afCfg InterfaceAddressFamilyConfig
		if err := json.Unmarshal([]byte(jsonStr), &afCfg); err == nil && (afCfg.Name != "" || afCfg.AdminState != "" || afCfg.Passive != nil || afCfg.HelloInterval != nil || afCfg.HoldTime != nil || afCfg.SplitHorizon != nil || afCfg.NextHopSelf != nil || afCfg.BandwidthPercent != nil || afCfg.Authentication != nil || afCfg.Bfd != nil) {
			if afCfg.Name == "" {
				afCfg.Name = afName
			}
			if afCfg.AdminState != "" {
				inst.defaultIntf.SetAfiAdminState(afCfg.Name, afCfg.AdminState)
			}
			if afCfg.Passive != nil {
				inst.defaultIntf.SetAfiPassive(afCfg.Name, afCfg.Passive)
			}
			if afCfg.HelloInterval != nil {
				inst.defaultIntf.SetAfiHelloInterval(afCfg.Name, afCfg.HelloInterval)
			}
			if afCfg.HoldTime != nil {
				inst.defaultIntf.SetAfiHoldTime(afCfg.Name, afCfg.HoldTime)
			}
			if afCfg.SplitHorizon != nil {
				inst.defaultIntf.SetAfiSplitHorizon(afCfg.Name, afCfg.SplitHorizon)
			}
			if afCfg.NextHopSelf != nil {
				inst.defaultIntf.SetAfiNextHopSelf(afCfg.Name, afCfg.NextHopSelf)
			}
			if afCfg.BandwidthPercent != nil {
				inst.defaultIntf.SetAfiBandwidthPercent(afCfg.Name, afCfg.BandwidthPercent)
			}
			if afCfg.Authentication != nil {
				inst.defaultIntf.SetAfiAuthentication(afCfg.Name, afCfg.Authentication)
			}
			if afCfg.Bfd != nil {
				inst.defaultIntf.SetAfiBfd(afCfg.Name, afCfg.Bfd)
			}
		} else {
			if strings.Contains(jsPath, ".passive") {
				var p bool
				if err := json.Unmarshal([]byte(jsonStr), &p); err == nil {
					inst.defaultIntf.SetAfiPassive(afName, &p)
				} else {
					var leaf struct {
						Passive bool `json:"passive"`
					}
					if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
						inst.defaultIntf.SetAfiPassive(afName, &leaf.Passive)
					}
				}
			} else if strings.Contains(jsPath, ".hello-interval") {
				var h uint16
				if err := json.Unmarshal([]byte(jsonStr), &h); err == nil {
					inst.defaultIntf.SetAfiHelloInterval(afName, &h)
				} else {
					var leaf struct {
						HelloInterval uint16 `json:"hello-interval"`
					}
					if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
						inst.defaultIntf.SetAfiHelloInterval(afName, &leaf.HelloInterval)
					}
				}
			} else if strings.Contains(jsPath, ".hold-time") {
				var h uint16
				if err := json.Unmarshal([]byte(jsonStr), &h); err == nil {
					inst.defaultIntf.SetAfiHoldTime(afName, &h)
				} else {
					var leaf struct {
						HoldTime uint16 `json:"hold-time"`
					}
					if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
						inst.defaultIntf.SetAfiHoldTime(afName, &leaf.HoldTime)
					}
				}
			} else if strings.Contains(jsPath, ".split-horizon") {
				var sh bool
				if err := json.Unmarshal([]byte(jsonStr), &sh); err == nil {
					inst.defaultIntf.SetAfiSplitHorizon(afName, &sh)
				} else {
					var leaf struct {
						SplitHorizon bool `json:"split-horizon"`
					}
					if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
						inst.defaultIntf.SetAfiSplitHorizon(afName, &leaf.SplitHorizon)
					}
				}
			} else if strings.Contains(jsPath, ".next-hop-self") {
				var nhs bool
				if err := json.Unmarshal([]byte(jsonStr), &nhs); err == nil {
					inst.defaultIntf.SetAfiNextHopSelf(afName, &nhs)
				} else {
					var leaf struct {
						NextHopSelf bool `json:"next-hop-self"`
					}
					if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
						inst.defaultIntf.SetAfiNextHopSelf(afName, &leaf.NextHopSelf)
					}
				}
			} else if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
				var bp uint32
				if err := json.Unmarshal([]byte(jsonStr), &bp); err == nil && bp > 0 {
					inst.defaultIntf.SetAfiBandwidthPercent(afName, &bp)
				} else {
					var leaf struct {
						BandwidthPercent uint32 `json:"bandwidth-percent"`
					}
					if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.BandwidthPercent > 0 {
						inst.defaultIntf.SetAfiBandwidthPercent(afName, &leaf.BandwidthPercent)
					}
				}
			} else if strings.Contains(jsPath, ".admin-state") {
				var s string
				if err := json.Unmarshal([]byte(jsonStr), &s); err == nil && s != "" {
					inst.defaultIntf.SetAfiAdminState(afName, s)
				} else {
					var leaf struct {
						AdminState string `json:"admin-state"`
					}
					if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.AdminState != "" {
						inst.defaultIntf.SetAfiAdminState(afName, leaf.AdminState)
					}
				}
			} else if strings.Contains(jsPath, ".authentication") {
				var auth AuthConfig
				if err := json.Unmarshal([]byte(jsonStr), &auth); err == nil && (auth.Mode != "" || auth.Keychain != "" || auth.AuthenticationKey != "" || auth.AdminState != "") {
					inst.defaultIntf.SetAfiAuthentication(afName, &auth)
				} else {
					cur := inst.defaultIntf.GetAfiAuthentication(afName)
					var newAuth AuthConfig
					if cur != nil {
						newAuth = *cur
					}
					if strings.Contains(jsPath, ".mode") {
						var m string
						if err := json.Unmarshal([]byte(jsonStr), &m); err == nil {
							newAuth.Mode = m
							inst.defaultIntf.SetAfiAuthentication(afName, &newAuth)
						}
					} else if strings.Contains(jsPath, ".keychain") {
						var kc string
						if err := json.Unmarshal([]byte(jsonStr), &kc); err == nil {
							newAuth.Keychain = kc
							inst.defaultIntf.SetAfiAuthentication(afName, &newAuth)
						}
					} else if strings.Contains(jsPath, ".authentication-key") || strings.Contains(jsPath, ".authentication_key") {
						var k string
						if err := json.Unmarshal([]byte(jsonStr), &k); err == nil {
							newAuth.AuthenticationKey = k
							inst.defaultIntf.SetAfiAuthentication(afName, &newAuth)
						}
					} else if strings.Contains(jsPath, ".admin-state") {
						var s string
						if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
							newAuth.AdminState = s
							inst.defaultIntf.SetAfiAuthentication(afName, &newAuth)
						}
					}
				}
			} else if strings.Contains(jsPath, ".bfd") {
				var bfd BfdConfig
				if err := json.Unmarshal([]byte(jsonStr), &bfd); err == nil && (bfd.AdminState != "" || bfd.DesiredMinimumTxInterval != nil || bfd.RequiredMinimumReceive != nil || bfd.DetectionMultiplier != nil) {
					inst.defaultIntf.SetAfiBfd(afName, &bfd)
				} else {
					cur := inst.defaultIntf.GetAfiBfd(afName)
					var newBfd BfdConfig
					if cur != nil {
						newBfd = *cur
					}
					if strings.Contains(jsPath, ".admin-state") {
						var s string
						if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
							newBfd.AdminState = s
							inst.defaultIntf.SetAfiBfd(afName, &newBfd)
						}
					} else if strings.Contains(jsPath, ".desired-minimum-tx-interval") {
						var v uint32
						if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
							newBfd.DesiredMinimumTxInterval = &v
							inst.defaultIntf.SetAfiBfd(afName, &newBfd)
						}
					} else if strings.Contains(jsPath, ".required-minimum-receive") {
						var v uint32
						if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
							newBfd.RequiredMinimumReceive = &v
							inst.defaultIntf.SetAfiBfd(afName, &newBfd)
						}
					} else if strings.Contains(jsPath, ".detection-multiplier") {
						var v uint8
						if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
							newBfd.DetectionMultiplier = &v
							inst.defaultIntf.SetAfiBfd(afName, &newBfd)
						}
					}
				}
			}
		}
		intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
		for _, ic := range inst.configuredInterfaces {
			intfs = append(intfs, ic)
		}
		d.mu.Unlock()
		for _, ic := range intfs {
			d.applyInterface(inst, ic)
		}
		log.Info().Str("netinst", netinst).Str("af", afName).Msg("Configured default-interface address-family and refreshed interfaces")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 2. Handle sub-path default-interface notification
	if strings.Contains(jsPath, ".protocols.eigrp.default-interface") && !strings.Contains(jsPath, ".address-family") {
		inst := d.GetOrCreateInstance(netinst)

		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			if strings.Contains(jsPath, ".authentication") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.Authentication = nil
				}
				log.Info().Str("netinst", netinst).Msg("Deleted default-interface authentication and refreshed interfaces")
			} else if strings.Contains(jsPath, ".bfd") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.Bfd = nil
				}
				log.Info().Str("netinst", netinst).Msg("Deleted default-interface bfd and refreshed interfaces")
			} else if strings.Contains(jsPath, ".passive") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.Passive = false
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface passive to default and refreshed interfaces")
			} else if strings.Contains(jsPath, ".delay") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.Delay = nil
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface delay to default and refreshed interfaces")
			} else if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.BandwidthPercent = nil
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface bandwidth-percent to default and refreshed interfaces")
			} else if strings.Contains(jsPath, ".bandwidth") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.Bandwidth = nil
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface bandwidth to default and refreshed interfaces")
			} else if strings.Contains(jsPath, ".hello-interval") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.HelloInterval = 0
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface hello-interval to default and refreshed interfaces")
			} else if strings.Contains(jsPath, ".hold-time") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.HoldTime = 0
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface hold-time to default and refreshed interfaces")
			} else if strings.Contains(jsPath, ".split-horizon") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.SplitHorizon = nil
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface split-horizon to default and refreshed interfaces")
			} else if strings.Contains(jsPath, ".next-hop-self") {
				if inst.defaultIntf != nil {
					inst.defaultIntf.NextHopSelf = nil
				}
				log.Info().Str("netinst", netinst).Msg("Reset default-interface next-hop-self to default and refreshed interfaces")
			} else {
				inst.defaultIntf = nil
				log.Info().Str("netinst", netinst).Msg("Deleted default-interface config and refreshed interfaces")
			}
			intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
			for _, ic := range inst.configuredInterfaces {
				intfs = append(intfs, ic)
			}
			d.mu.Unlock()
			for _, ic := range intfs {
				d.applyInterface(inst, ic)
			}
			go d.CollectAndPublish(context.Background())
			return
		}

		d.mu.Lock()
		if inst.defaultIntf == nil {
			inst.defaultIntf = &DefaultInterfaceConfig{AdminState: "enable"}
		}
		if strings.Contains(jsPath, ".admin-state") {
			var s string
			if err := json.Unmarshal([]byte(jsonStr), &s); err == nil && s != "" {
				inst.defaultIntf.AdminState = s
			} else {
				var leaf struct {
					AdminState string `json:"admin-state"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.AdminState != "" {
					inst.defaultIntf.AdminState = leaf.AdminState
				}
			}
		} else if strings.Contains(jsPath, ".passive") {
			var pVal bool
			if err := json.Unmarshal([]byte(jsonStr), &pVal); err == nil {
				inst.defaultIntf.Passive = pVal
			} else {
				var leaf struct {
					Passive bool `json:"passive"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					inst.defaultIntf.Passive = leaf.Passive
				}
			}
		} else if strings.Contains(jsPath, ".delay") {
			var dVal uint32
			if err := json.Unmarshal([]byte(jsonStr), &dVal); err == nil {
				inst.defaultIntf.Delay = &dVal
			} else {
				var leaf struct {
					Delay uint32 `json:"delay"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					inst.defaultIntf.Delay = &leaf.Delay
				}
			}
		} else if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
			var bpVal uint32
			if err := json.Unmarshal([]byte(jsonStr), &bpVal); err == nil && bpVal > 0 {
				inst.defaultIntf.BandwidthPercent = &bpVal
			} else {
				var leaf struct {
					BandwidthPercent uint32 `json:"bandwidth-percent"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.BandwidthPercent > 0 {
					inst.defaultIntf.BandwidthPercent = &leaf.BandwidthPercent
				}
			}
		} else if strings.Contains(jsPath, ".bandwidth") {
			var bVal uint32
			if err := json.Unmarshal([]byte(jsonStr), &bVal); err == nil {
				inst.defaultIntf.Bandwidth = &bVal
			} else {
				var leaf struct {
					Bandwidth uint32 `json:"bandwidth"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					inst.defaultIntf.Bandwidth = &leaf.Bandwidth
				}
			}
		} else if strings.Contains(jsPath, ".hello-interval") {
			var hVal uint16
			if err := json.Unmarshal([]byte(jsonStr), &hVal); err == nil {
				inst.defaultIntf.HelloInterval = hVal
			} else {
				var leaf struct {
					HelloInterval uint16 `json:"hello-interval"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					inst.defaultIntf.HelloInterval = leaf.HelloInterval
				}
			}
		} else if strings.Contains(jsPath, ".hold-time") {
			var hVal uint16
			if err := json.Unmarshal([]byte(jsonStr), &hVal); err == nil {
				inst.defaultIntf.HoldTime = hVal
			} else {
				var leaf struct {
					HoldTime uint16 `json:"hold-time"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					inst.defaultIntf.HoldTime = leaf.HoldTime
				}
			}
		} else if strings.Contains(jsPath, ".split-horizon") {
			var shVal bool
			if err := json.Unmarshal([]byte(jsonStr), &shVal); err == nil {
				inst.defaultIntf.SplitHorizon = &shVal
			} else {
				var leaf struct {
					SplitHorizon bool `json:"split-horizon"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					inst.defaultIntf.SplitHorizon = &leaf.SplitHorizon
				}
			}
		} else if strings.Contains(jsPath, ".next-hop-self") {
			var nhsVal bool
			if err := json.Unmarshal([]byte(jsonStr), &nhsVal); err == nil {
				inst.defaultIntf.NextHopSelf = &nhsVal
			} else {
				var leaf struct {
					NextHopSelf bool `json:"next-hop-self"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					inst.defaultIntf.NextHopSelf = &leaf.NextHopSelf
				}
			}
		} else if strings.Contains(jsPath, ".authentication") {
			var authCfg AuthConfig
			if err := json.Unmarshal([]byte(jsonStr), &authCfg); err == nil && (authCfg.Mode != "" || authCfg.Keychain != "" || authCfg.AuthenticationKey != "" || authCfg.AdminState != "") {
				inst.defaultIntf.Authentication = &authCfg
			} else {
				cur := inst.defaultIntf.Authentication
				var newAuth AuthConfig
				if cur != nil {
					newAuth = *cur
				}
				if strings.Contains(jsPath, ".mode") {
					var m string
					if err := json.Unmarshal([]byte(jsonStr), &m); err == nil {
						newAuth.Mode = m
						inst.defaultIntf.Authentication = &newAuth
					}
				} else if strings.Contains(jsPath, ".keychain") {
					var kc string
					if err := json.Unmarshal([]byte(jsonStr), &kc); err == nil {
						newAuth.Keychain = kc
						inst.defaultIntf.Authentication = &newAuth
					}
				} else if strings.Contains(jsPath, ".authentication-key") || strings.Contains(jsPath, ".authentication_key") {
					var k string
					if err := json.Unmarshal([]byte(jsonStr), &k); err == nil {
						newAuth.AuthenticationKey = k
						inst.defaultIntf.Authentication = &newAuth
					}
				} else if strings.Contains(jsPath, ".admin-state") {
					var s string
					if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
						newAuth.AdminState = s
						inst.defaultIntf.Authentication = &newAuth
					}
				}
			}
		} else if strings.Contains(jsPath, ".bfd") {
			var bfdCfg BfdConfig
			if err := json.Unmarshal([]byte(jsonStr), &bfdCfg); err == nil && (bfdCfg.AdminState != "" || bfdCfg.DesiredMinimumTxInterval != nil || bfdCfg.RequiredMinimumReceive != nil || bfdCfg.DetectionMultiplier != nil) {
				inst.defaultIntf.Bfd = &bfdCfg
			} else {
				cur := inst.defaultIntf.Bfd
				var newBfd BfdConfig
				if cur != nil {
					newBfd = *cur
				}
				if strings.Contains(jsPath, ".admin-state") {
					var s string
					if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
						newBfd.AdminState = s
						inst.defaultIntf.Bfd = &newBfd
					}
				} else if strings.Contains(jsPath, ".desired-minimum-tx-interval") {
					var v uint32
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.DesiredMinimumTxInterval = &v
						inst.defaultIntf.Bfd = &newBfd
					}
				} else if strings.Contains(jsPath, ".required-minimum-receive") {
					var v uint32
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.RequiredMinimumReceive = &v
						inst.defaultIntf.Bfd = &newBfd
					}
				} else if strings.Contains(jsPath, ".detection-multiplier") {
					var v uint8
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.DetectionMultiplier = &v
						inst.defaultIntf.Bfd = &newBfd
					}
				}
			}
		} else {
			var defCfg DefaultInterfaceConfig
			if err := json.Unmarshal([]byte(jsonStr), &defCfg); err == nil {
				if defCfg.AdminState != "" {
					inst.defaultIntf.AdminState = defCfg.AdminState
				}
				inst.defaultIntf.Passive = defCfg.Passive
				if defCfg.HelloInterval != 0 {
					inst.defaultIntf.HelloInterval = defCfg.HelloInterval
				}
				if defCfg.HoldTime != 0 {
					inst.defaultIntf.HoldTime = defCfg.HoldTime
				}
				if defCfg.SplitHorizon != nil {
					inst.defaultIntf.SplitHorizon = defCfg.SplitHorizon
				}
				if defCfg.NextHopSelf != nil {
					inst.defaultIntf.NextHopSelf = defCfg.NextHopSelf
				}
				if defCfg.Bandwidth != nil {
					inst.defaultIntf.Bandwidth = defCfg.Bandwidth
				}
				if defCfg.BandwidthPercent != nil {
					inst.defaultIntf.BandwidthPercent = defCfg.BandwidthPercent
				}
				if defCfg.Delay != nil {
					inst.defaultIntf.Delay = defCfg.Delay
				}
				if defCfg.Authentication != nil {
					inst.defaultIntf.Authentication = defCfg.Authentication
				}
				if defCfg.Bfd != nil {
					inst.defaultIntf.Bfd = defCfg.Bfd
				}
				if len(defCfg.AddressFamily) > 0 {
					inst.defaultIntf.AddressFamily = defCfg.AddressFamily
				}
			}
		}
		if inst.defaultIntf.AdminState == "" {
			inst.defaultIntf.AdminState = "enable"
		}
		intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
		for _, ic := range inst.configuredInterfaces {
			intfs = append(intfs, ic)
		}
		d.mu.Unlock()
		for _, ic := range intfs {
			d.applyInterface(inst, ic)
		}
		log.Info().Str("netinst", netinst).Interface("default_interface", inst.defaultIntf).Msg("Updated default-interface config and refreshed interfaces")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 3. Handle sub-path timers notification
	if strings.Contains(jsPath, ".protocols.eigrp.timers") {
		var t TimersConfig
		if err := json.Unmarshal([]byte(jsonStr), &t); err == nil {
			inst := d.GetOrCreateInstance(netinst)
			d.mu.Lock()
			inst.timers = &t
			d.mu.Unlock()
			d.applyTimers(netinst, &t)
			log.Info().Str("netinst", netinst).Interface("timers", t).Msg("Updated EIGRP timers via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 4. Handle sub-path variance notification
	if strings.Contains(jsPath, ".protocols.eigrp.variance") {
		v := uint8(1)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			v = 1
		} else {
			if err := json.Unmarshal([]byte(jsonStr), &v); err != nil || v == 0 {
				var leaf struct {
					Variance uint8 `json:"variance"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.Variance > 0 {
					v = leaf.Variance
				} else {
					v = 1
				}
			}
		}
		cNetinst := C.CString(netinst)
		C.srlShimVarianceUpdate(cNetinst, C.uint8_t(v))
		C.free(unsafe.Pointer(cNetinst))
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		inst.variance = v
		d.mu.Unlock()
		log.Info().Str("netinst", netinst).Uint8("variance", v).Msg("Updated EIGRP variance via sub-path notification")
		if v > 1 {
			log.Info().Str("netinst", netinst).Uint8("variance", v).Msg("EIGRP variance > 1 configured: feasible successor routes within variance window are installed into FIB as uniform ECMP multipath due to NDK schema boundaries")
		}
		go d.CollectAndPublish(context.Background())
		return
	}

	// 5. Handle sub-path maximum-paths notification
	if strings.Contains(jsPath, ".protocols.eigrp.maximum-paths") {
		mp := uint8(4)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			mp = 4
		} else {
			if err := json.Unmarshal([]byte(jsonStr), &mp); err != nil || mp == 0 {
				var leaf struct {
					MaximumPaths uint8 `json:"maximum-paths"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.MaximumPaths > 0 {
					mp = leaf.MaximumPaths
				} else {
					mp = 4
				}
			}
		}
		cNetinst := C.CString(netinst)
		C.srlShimMaxPathsUpdate(cNetinst, C.uint8_t(mp))
		C.free(unsafe.Pointer(cNetinst))
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		inst.maximumPaths = mp
		d.mu.Unlock()
		log.Info().Str("netinst", netinst).Uint8("maximum_paths", mp).Msg("Updated EIGRP maximum-paths via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6. Handle sub-path maximum-hops notification
	if strings.Contains(jsPath, ".protocols.eigrp.maximum-hops") {
		mh := uint8(100)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			mh = 100
		} else {
			if err := json.Unmarshal([]byte(jsonStr), &mh); err != nil || mh == 0 {
				var leaf struct {
					MaximumHops uint8 `json:"maximum-hops"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.MaximumHops > 0 {
					mh = leaf.MaximumHops
				} else {
					mh = 100
				}
			}
		}
		cNetinst := C.CString(netinst)
		C.srlShimMaxHopsUpdate(cNetinst, C.uint8_t(mh))
		C.free(unsafe.Pointer(cNetinst))
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		inst.maximumHops = mh
		d.mu.Unlock()
		log.Info().Str("netinst", netinst).Uint8("maximum_hops", mh).Msg("Updated EIGRP maximum-hops via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6a. Handle sub-path graceful-restart notification
	if strings.Contains(jsPath, ".protocols.eigrp.graceful-restart") || strings.Contains(jsPath, ".protocols.eigrp.graceful_restart") {
		inst := d.GetOrCreateInstance(netinst)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			inst.gracefulRestart = nil
			inst.restarting = false
			d.mu.Unlock()
			d.applyGracefulRestart(netinst, nil)
			log.Info().Str("netinst", netinst).Msg("Removed graceful-restart config via sub-path notification")
			go d.CollectAndPublish(context.Background())
			return
		}
		var gr GracefulRestartConfig
		if err := json.Unmarshal([]byte(jsonStr), &gr); err == nil {
			d.mu.Lock()
			inst.gracefulRestart = &gr
			if gr.AdminState == "disable" {
				inst.restarting = false
			}
			d.mu.Unlock()
			d.applyGracefulRestart(netinst, &gr)
			log.Info().Str("netinst", netinst).Interface("graceful_restart", gr).Msg("Updated EIGRP graceful-restart via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 6b. Handle sub-path rib-scale notification
	if strings.Contains(jsPath, "rib-scale") || strings.Contains(jsPath, "rib_scale") {
		inst := d.GetOrCreateInstance(netinst)
		var scale uint8 = 128
		if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if err := json.Unmarshal([]byte(jsonStr), &scale); err != nil || scale == 0 {
				scale = 128
			}
		}
		d.mu.Lock()
		inst.ribScale = scale
		curMetrics := inst.metrics
		wm := inst.wideMetrics
		d.mu.Unlock()
		cNetinst := C.CString(netinst)
		C.srl_set_rib_scale(cNetinst, C.uint8_t(scale))
		C.free(unsafe.Pointer(cNetinst))
		d.applyMetrics(netinst, curMetrics, scale, wm)
		log.Info().Str("netinst", netinst).Uint8("rib_scale", scale).Msg("Updated EIGRP rib-scale via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6c. Handle sub-path wide-metrics notification
	if strings.Contains(jsPath, ".protocols.eigrp.wide-metrics") || strings.Contains(jsPath, ".protocols.eigrp.wide_metrics") {
		inst := d.GetOrCreateInstance(netinst)
		var wm bool = true
		if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			_ = json.Unmarshal([]byte(jsonStr), &wm)
		}
		d.mu.Lock()
		inst.wideMetrics = wm
		curMetrics := inst.metrics
		scale := inst.ribScale
		d.mu.Unlock()
		d.applyMetrics(netinst, curMetrics, scale, wm)
		log.Info().Str("netinst", netinst).Bool("wide_metrics", wm).Msg("Updated EIGRP wide-metrics via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6c2. Handle sub-path traffic-share-balanced notification
	if (strings.Contains(jsPath, ".protocols.eigrp.traffic-share-balanced") || strings.Contains(jsPath, ".protocols.eigrp.traffic_share_balanced")) && !strings.Contains(jsPath, ".address-family") {
		inst := d.GetOrCreateInstance(netinst)
		var tsb bool = false
		if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if err := json.Unmarshal([]byte(jsonStr), &tsb); err != nil {
				var leaf struct {
					TrafficShareBalanced bool `json:"traffic-share-balanced"`
				}
				_ = json.Unmarshal([]byte(jsonStr), &leaf)
				tsb = leaf.TrafficShareBalanced
			}
		}
		d.mu.Lock()
		inst.trafficShareBalanced = tsb
		d.mu.Unlock()
		d.applyInstanceFeatures(inst)
		log.Info().Str("netinst", netinst).Bool("traffic_share_balanced", tsb).Msg("Updated EIGRP traffic-share-balanced via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6c3. Handle sub-path auto-summary notification
	if (strings.Contains(jsPath, ".protocols.eigrp.auto-summary") || strings.Contains(jsPath, ".protocols.eigrp.auto_summary")) && !strings.Contains(jsPath, ".address-family") {
		inst := d.GetOrCreateInstance(netinst)
		var as bool = false
		if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if err := json.Unmarshal([]byte(jsonStr), &as); err != nil {
				var leaf struct {
					AutoSummary bool `json:"auto-summary"`
				}
				_ = json.Unmarshal([]byte(jsonStr), &leaf)
				as = leaf.AutoSummary
			}
		}
		d.mu.Lock()
		inst.autoSummary = as
		d.mu.Unlock()
		d.applyInstanceFeatures(inst)
		log.Info().Str("netinst", netinst).Bool("auto_summary", as).Msg("Updated EIGRP auto-summary via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6c4. Handle sub-path event-log-size notification
	if strings.Contains(jsPath, ".protocols.eigrp.event-log-size") || strings.Contains(jsPath, ".protocols.eigrp.event_log_size") {
		inst := d.GetOrCreateInstance(netinst)
		var evSize uint32 = 500
		if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if err := json.Unmarshal([]byte(jsonStr), &evSize); err != nil || evSize == 0 {
				var leaf struct {
					EventLogSize uint32 `json:"event-log-size"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.EventLogSize > 0 {
					evSize = leaf.EventLogSize
				} else {
					evSize = 500
				}
			}
		}
		d.mu.Lock()
		inst.eventLogSize = evSize
		d.mu.Unlock()
		d.applyInstanceFeatures(inst)
		log.Info().Str("netinst", netinst).Uint32("event_log_size", evSize).Msg("Updated EIGRP event-log-size via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6c5. Handle sub-path default-metric notification
	if (strings.Contains(jsPath, ".protocols.eigrp.default-metric") || strings.Contains(jsPath, ".protocols.eigrp.default_metric")) && !strings.Contains(jsPath, ".address-family") {
		inst := d.GetOrCreateInstance(netinst)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			inst.defaultMetric = nil
			d.mu.Unlock()
			d.applyInstanceFeatures(inst)
			d.TriggerRedistSync(netinst)
			go d.CollectAndPublish(context.Background())
			return
		}
		d.mu.Lock()
		dm := parseDefaultMetricNotif(jsPath, jsonStr, inst.defaultMetric)
		inst.defaultMetric = dm
		d.mu.Unlock()
		if dm != nil {
			d.applyInstanceFeatures(inst)
			d.TriggerRedistSync(netinst)
			log.Info().Str("netinst", netinst).Interface("default_metric", dm).Msg("Updated EIGRP default-metric via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 6c6. Handle sub-path maximum-prefix notification
	if (strings.Contains(jsPath, ".protocols.eigrp.maximum-prefix") || strings.Contains(jsPath, ".protocols.eigrp.maximum_prefix")) && !strings.Contains(jsPath, ".address-family") {
		inst := d.GetOrCreateInstance(netinst)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			if strings.Contains(jsPath, ".warning-only") || strings.Contains(jsPath, ".warning_only") {
				if inst.maximumPrefix != nil {
					inst.maximumPrefix.WarningOnly = nil
				}
			} else if strings.Contains(jsPath, ".threshold") {
				if inst.maximumPrefix != nil {
					inst.maximumPrefix.Threshold = 75
				}
			} else {
				inst.maximumPrefix = nil
			}
			d.mu.Unlock()
			d.applyInstanceFeatures(inst)
			go d.CollectAndPublish(context.Background())
			return
		}
		d.mu.Lock()
		mp := parseMaxPrefixNotif(jsPath, jsonStr, inst.maximumPrefix)
		inst.maximumPrefix = mp
		d.mu.Unlock()
		if mp != nil {
			d.applyInstanceFeatures(inst)
			log.Info().Str("netinst", netinst).Interface("maximum_prefix", mp).Msg("Updated EIGRP maximum-prefix via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 6d. Handle sub-path preference notification
	if strings.Contains(jsPath, ".protocols.eigrp.preference") && !strings.Contains(jsPath, ".address-family") {
		var pref uint8 = 90
		if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if err := json.Unmarshal([]byte(jsonStr), &pref); err != nil || pref == 0 {
				var leaf struct {
					Preference uint8 `json:"preference"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.Preference > 0 {
					pref = leaf.Preference
				} else {
					pref = 90
				}
			}
		}
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		inst.preference = pref
		extPref := inst.externalPreference
		if extPref == 0 {
			extPref = 170
		}
		d.mu.Unlock()
		cNetinst := C.CString(netinst)
		C.srlShimDistanceUpdate(cNetinst, C.uint8_t(pref), C.uint8_t(extPref))
		C.free(unsafe.Pointer(cNetinst))
		log.Info().Str("netinst", netinst).Uint8("preference", pref).Msg("Updated EIGRP preference via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 6e. Handle sub-path external-preference notification
	if (strings.Contains(jsPath, ".protocols.eigrp.external-preference") || strings.Contains(jsPath, ".protocols.eigrp.external_preference")) && !strings.Contains(jsPath, ".address-family") {
		var extPref uint8 = 170
		if op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if err := json.Unmarshal([]byte(jsonStr), &extPref); err != nil || extPref == 0 {
				var leaf struct {
					ExternalPreference uint8 `json:"external-preference"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.ExternalPreference > 0 {
					extPref = leaf.ExternalPreference
				} else {
					extPref = 170
				}
			}
		}
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		inst.externalPreference = extPref
		intPref := inst.preference
		if intPref == 0 {
			intPref = 90
		}
		d.mu.Unlock()
		cNetinst := C.CString(netinst)
		C.srlShimDistanceUpdate(cNetinst, C.uint8_t(intPref), C.uint8_t(extPref))
		C.free(unsafe.Pointer(cNetinst))
		log.Info().Str("netinst", netinst).Uint8("external_preference", extPref).Msg("Updated EIGRP external-preference via sub-path notification")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 7. Handle sub-path metrics notification
	if strings.Contains(jsPath, ".protocols.eigrp.metrics") || strings.Contains(jsPath, ".protocols.eigrp.metric-weights") {
		var m MetricsConfig
		if err := json.Unmarshal([]byte(jsonStr), &m); err == nil {
			inst := d.GetOrCreateInstance(netinst)
			d.mu.Lock()
			inst.metrics = &m
			if strings.Contains(jsPath, ".metric-weights") {
				inst.metricWeights = &m
			}
			if m.RibScale != nil && *m.RibScale > 0 {
				inst.ribScale = *m.RibScale
			}
			scale := inst.ribScale
			wm := inst.wideMetrics
			d.mu.Unlock()
			cNetinst := C.CString(netinst)
			C.srl_set_rib_scale(cNetinst, C.uint8_t(scale))
			C.free(unsafe.Pointer(cNetinst))
			d.applyMetrics(netinst, &m, scale, wm)
			log.Info().Str("netinst", netinst).Interface("metrics", m).Msg("Updated EIGRP metrics via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 8a. Handle sub-path interface address-family notification
	if strings.Contains(jsPath, ".protocols.eigrp.interface") && (strings.Contains(jsPath, ".address-family") || strings.Contains(jsPath, ".address_family")) && !strings.Contains(jsPath, ".default-interface") && !strings.Contains(jsPath, ".default_interface") {
		ifName := extractIntfName(cfg)
		afName := extractAfName(cfg)
		if ifName == "" || afName == "" {
			return
		}
		inst := d.GetOrCreateInstance(netinst)
		d.mu.Lock()
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			ic, exists := inst.configuredInterfaces[ifName]
			if !exists || ic == nil {
				d.mu.Unlock()
				return
			}
			if strings.Contains(jsPath, ".summary-address") {
				pfx := extractSummaryPrefix(cfg)
				if strings.Contains(jsPath, ".distance") && pfx != "" {
					ic.AddOrUpdateAfiSummaryAddress(afName, SummaryAddressConfig{Prefix: pfx, Distance: 5})
					d.mu.Unlock()
					d.applyInterface(inst, ic)
					go d.CollectAndPublish(context.Background())
					return
				}
				var deletedPfxs []string
				if pfx != "" {
					deletedPfxs = append(deletedPfxs, pfx)
				} else {
					for _, sa := range ic.GetAfiSummaryAddresses(afName) {
						if sa.Prefix != "" {
							deletedPfxs = append(deletedPfxs, sa.Prefix)
						}
					}
				}
				ic.DeleteAfiSummaryAddress(afName, pfx)
				d.mu.Unlock()
				cNetinst := C.CString(netinst)
				cIfname := C.CString(ifName)
				for _, dp := range deletedPfxs {
					cPfx := C.CString(dp)
					C.srlShimSummaryAddressDelete(cNetinst, cIfname, cPfx)
					C.free(unsafe.Pointer(cPfx))
				}
				C.free(unsafe.Pointer(cNetinst))
				C.free(unsafe.Pointer(cIfname))
				d.applyInterface(inst, ic)
				log.Info().Str("netinst", netinst).Str("interface", ifName).Str("af", afName).Str("prefix", pfx).Msg("Deleted summary-address on interface AF")
				go d.CollectAndPublish(context.Background())
				return
			} else if strings.Contains(jsPath, ".passive") {
				ic.SetAfiPassive(afName, nil)
			} else if strings.Contains(jsPath, ".hello-interval") {
				ic.SetAfiHelloInterval(afName, nil)
			} else if strings.Contains(jsPath, ".hold-time") {
				ic.SetAfiHoldTime(afName, nil)
			} else if strings.Contains(jsPath, ".split-horizon") {
				ic.SetAfiSplitHorizon(afName, nil)
			} else if strings.Contains(jsPath, ".next-hop-self") {
				ic.SetAfiNextHopSelf(afName, nil)
			} else if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
				ic.SetAfiBandwidthPercent(afName, nil)
			} else if strings.Contains(jsPath, ".authentication") {
				ic.SetAfiAuthentication(afName, nil)
			} else if strings.Contains(jsPath, ".bfd") {
				ic.SetAfiBfd(afName, nil)
			} else if strings.Contains(jsPath, ".admin-state") {
				ic.SetAfiAdminState(afName, "")
			} else {
				var updatedAF []InterfaceAddressFamilyConfig
				for _, af := range ic.AddressFamily {
					if af.Name != afName {
						updatedAF = append(updatedAF, af)
					}
				}
				ic.AddressFamily = updatedAF
			}
			d.mu.Unlock()
			d.applyInterface(inst, ic)
			log.Info().Str("netinst", netinst).Str("interface", ifName).Str("af", afName).Msg("Deleted address-family property on interface")
			go d.CollectAndPublish(context.Background())
			return
		}

		ic, exists := inst.configuredInterfaces[ifName]
		if !exists || ic == nil {
			ic = &InterfaceConfig{InterfaceName: ifName}
			inst.configuredInterfaces[ifName] = ic
		}

		if strings.Contains(jsPath, ".summary-address") {
			pfx := extractSummaryPrefix(cfg)
			var saCfg SummaryAddressConfig
			if err := json.Unmarshal([]byte(jsonStr), &saCfg); err != nil && strings.Contains(jsPath, ".distance") {
				var dist uint8
				if err2 := json.Unmarshal([]byte(jsonStr), &dist); err2 == nil {
					saCfg.Distance = dist
				}
			}
			if saCfg.Prefix == "" && pfx != "" {
				saCfg.Prefix = pfx
			}
			if saCfg.Distance == 0 {
				saCfg.Distance = 5
			}
			ic.AddOrUpdateAfiSummaryAddress(afName, saCfg)
		} else if strings.Contains(jsPath, ".passive") {
			var p bool
			if err := json.Unmarshal([]byte(jsonStr), &p); err == nil {
				ic.SetAfiPassive(afName, &p)
			} else {
				var leaf struct {
					Passive bool `json:"passive"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.SetAfiPassive(afName, &leaf.Passive)
				}
			}
		} else if strings.Contains(jsPath, ".hello-interval") {
			var h uint16
			if err := json.Unmarshal([]byte(jsonStr), &h); err == nil {
				ic.SetAfiHelloInterval(afName, &h)
			} else {
				var leaf struct {
					HelloInterval uint16 `json:"hello-interval"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.SetAfiHelloInterval(afName, &leaf.HelloInterval)
				}
			}
		} else if strings.Contains(jsPath, ".hold-time") {
			var h uint16
			if err := json.Unmarshal([]byte(jsonStr), &h); err == nil {
				ic.SetAfiHoldTime(afName, &h)
			} else {
				var leaf struct {
					HoldTime uint16 `json:"hold-time"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.SetAfiHoldTime(afName, &leaf.HoldTime)
				}
			}
		} else if strings.Contains(jsPath, ".split-horizon") {
			var sh bool
			if err := json.Unmarshal([]byte(jsonStr), &sh); err == nil {
				ic.SetAfiSplitHorizon(afName, &sh)
			} else {
				var leaf struct {
					SplitHorizon bool `json:"split-horizon"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.SetAfiSplitHorizon(afName, &leaf.SplitHorizon)
				}
			}
		} else if strings.Contains(jsPath, ".next-hop-self") {
			var nhs bool
			if err := json.Unmarshal([]byte(jsonStr), &nhs); err == nil {
				ic.SetAfiNextHopSelf(afName, &nhs)
			} else {
				var leaf struct {
					NextHopSelf bool `json:"next-hop-self"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.SetAfiNextHopSelf(afName, &leaf.NextHopSelf)
				}
			}
		} else if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
			var bp uint32
			if err := json.Unmarshal([]byte(jsonStr), &bp); err == nil && bp > 0 {
				ic.SetAfiBandwidthPercent(afName, &bp)
			} else {
				var leaf struct {
					BandwidthPercent uint32 `json:"bandwidth-percent"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.BandwidthPercent > 0 {
					ic.SetAfiBandwidthPercent(afName, &leaf.BandwidthPercent)
				}
			}
		} else if strings.Contains(jsPath, ".admin-state") {
			var s string
			if err := json.Unmarshal([]byte(jsonStr), &s); err == nil && s != "" {
				ic.SetAfiAdminState(afName, s)
			} else {
				var leaf struct {
					AdminState string `json:"admin-state"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.AdminState != "" {
					ic.SetAfiAdminState(afName, leaf.AdminState)
				}
			}
		} else if strings.Contains(jsPath, ".authentication") {
			var auth AuthConfig
			if err := json.Unmarshal([]byte(jsonStr), &auth); err == nil && (auth.Mode != "" || auth.Keychain != "" || auth.AuthenticationKey != "" || auth.AdminState != "") {
				ic.SetAfiAuthentication(afName, &auth)
			} else {
				cur := ic.GetAfiAuthentication(afName, inst.defaultIntf, inst.authentication)
				var newAuth AuthConfig
				if cur != nil {
					newAuth = *cur
				}
				if strings.Contains(jsPath, ".mode") {
					var m string
					if err := json.Unmarshal([]byte(jsonStr), &m); err == nil {
						newAuth.Mode = m
						ic.SetAfiAuthentication(afName, &newAuth)
					}
				} else if strings.Contains(jsPath, ".keychain") {
					var kc string
					if err := json.Unmarshal([]byte(jsonStr), &kc); err == nil {
						newAuth.Keychain = kc
						ic.SetAfiAuthentication(afName, &newAuth)
					}
				} else if strings.Contains(jsPath, ".authentication-key") || strings.Contains(jsPath, ".authentication_key") {
					var k string
					if err := json.Unmarshal([]byte(jsonStr), &k); err == nil {
						newAuth.AuthenticationKey = k
						ic.SetAfiAuthentication(afName, &newAuth)
					}
				} else if strings.Contains(jsPath, ".admin-state") {
					var s string
					if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
						newAuth.AdminState = s
						ic.SetAfiAuthentication(afName, &newAuth)
					}
				}
			}
		} else if strings.Contains(jsPath, ".bfd") {
			var bfd BfdConfig
			if err := json.Unmarshal([]byte(jsonStr), &bfd); err == nil && (bfd.AdminState != "" || bfd.DesiredMinimumTxInterval != nil || bfd.RequiredMinimumReceive != nil || bfd.DetectionMultiplier != nil) {
				ic.SetAfiBfd(afName, &bfd)
			} else {
				cur := ic.GetAfiBfd(afName, inst.defaultIntf)
				var newBfd BfdConfig
				if cur != nil {
					newBfd = *cur
				}
				if strings.Contains(jsPath, ".admin-state") {
					var s string
					if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
						newBfd.AdminState = s
						ic.SetAfiBfd(afName, &newBfd)
					}
				} else if strings.Contains(jsPath, ".desired-minimum-tx-interval") {
					var v uint32
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.DesiredMinimumTxInterval = &v
						ic.SetAfiBfd(afName, &newBfd)
					}
				} else if strings.Contains(jsPath, ".required-minimum-receive") {
					var v uint32
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.RequiredMinimumReceive = &v
						ic.SetAfiBfd(afName, &newBfd)
					}
				} else if strings.Contains(jsPath, ".detection-multiplier") {
					var v uint8
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.DetectionMultiplier = &v
						ic.SetAfiBfd(afName, &newBfd)
					}
				}
			}
		} else {
			var afCfg InterfaceAddressFamilyConfig
			if err := json.Unmarshal([]byte(jsonStr), &afCfg); err == nil {
				if afCfg.Name == "" {
					afCfg.Name = afName
				}
				if afCfg.AdminState != "" {
					ic.SetAfiAdminState(afCfg.Name, afCfg.AdminState)
				}
				if afCfg.Passive != nil {
					ic.SetAfiPassive(afCfg.Name, afCfg.Passive)
				}
				if afCfg.HelloInterval != nil {
					ic.SetAfiHelloInterval(afCfg.Name, afCfg.HelloInterval)
				}
				if afCfg.HoldTime != nil {
					ic.SetAfiHoldTime(afCfg.Name, afCfg.HoldTime)
				}
				if afCfg.SplitHorizon != nil {
					ic.SetAfiSplitHorizon(afCfg.Name, afCfg.SplitHorizon)
				}
				if afCfg.NextHopSelf != nil {
					ic.SetAfiNextHopSelf(afCfg.Name, afCfg.NextHopSelf)
				}
				if afCfg.BandwidthPercent != nil {
					ic.SetAfiBandwidthPercent(afCfg.Name, afCfg.BandwidthPercent)
				}
				if afCfg.Authentication != nil {
					ic.SetAfiAuthentication(afCfg.Name, afCfg.Authentication)
				}
				if afCfg.Bfd != nil {
					ic.SetAfiBfd(afCfg.Name, afCfg.Bfd)
				}
				if len(afCfg.SummaryAddress) > 0 {
					for _, sa := range afCfg.SummaryAddress {
						ic.AddOrUpdateAfiSummaryAddress(afCfg.Name, sa)
					}
				}
			}
		}
		d.mu.Unlock()
		d.applyInterface(inst, ic)
		log.Info().Str("netinst", netinst).Str("interface", ifName).Str("af", afName).Interface("config", ic.AddressFamily).Msg("Configured address-family on interface")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 8b. Handle sub-path interface notification
	if strings.Contains(jsPath, ".protocols.eigrp.interface") && !strings.Contains(jsPath, ".default-interface") {
		ifName := extractIntfName(cfg)
		if ifName == "" {
			return
		}
		cNetinst := C.CString(netinst)
		defer C.free(unsafe.Pointer(cNetinst))
		cIfname := C.CString(ifName)
		defer C.free(unsafe.Pointer(cIfname))

		inst := d.GetOrCreateInstance(netinst)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if strings.Contains(jsPath, ".summary-address") {
				pfx := extractSummaryPrefix(cfg)
				d.mu.Lock()
				var ic *InterfaceConfig
				var deletedPfxs []string
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					ic = c
					if strings.Contains(jsPath, ".distance") && pfx != "" {
						for i, sa := range ic.SummaryAddress {
							if sa.Prefix == pfx {
								ic.SummaryAddress[i].Distance = 5
							}
						}
						d.mu.Unlock()
						d.applyInterface(inst, ic)
						go d.CollectAndPublish(context.Background())
						return
					}
					var updatedSA []SummaryAddressConfig
					if pfx != "" {
						deletedPfxs = append(deletedPfxs, pfx)
						for _, sa := range ic.SummaryAddress {
							if sa.Prefix != pfx {
								updatedSA = append(updatedSA, sa)
							}
						}
					} else {
						for _, sa := range ic.SummaryAddress {
							if sa.Prefix != "" {
								deletedPfxs = append(deletedPfxs, sa.Prefix)
							}
						}
					}
					ic.SummaryAddress = updatedSA
				}
				d.mu.Unlock()
				for _, dp := range deletedPfxs {
					cPfx := C.CString(dp)
					C.srlShimSummaryAddressDelete(cNetinst, cIfname, cPfx)
					C.free(unsafe.Pointer(cPfx))
				}
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Str("prefix", pfx).Msg("Deleted summary-address on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".authentication") {
				d.mu.Lock()
				if ic, exists := inst.configuredInterfaces[ifName]; exists {
					ic.Authentication = nil
				}
				d.mu.Unlock()
				C.srlShimInterfaceAuthClear(cNetinst, cIfname)
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Cleared EIGRP authentication on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".bfd") {
				d.mu.Lock()
				if ic, exists := inst.configuredInterfaces[ifName]; exists {
					ic.Bfd = nil
				}
				d.mu.Unlock()
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Cleared EIGRP bfd on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".admin-state") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.AdminState = "enable"
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset admin-state on interface to default enable")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".delay") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.Delay = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset delay on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.BandwidthPercent = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset bandwidth-percent on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".bandwidth") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.Bandwidth = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset bandwidth on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".passive") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.Passive = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset passive on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".hello-interval") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.HelloInterval = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset hello-interval on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".hold-time") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.HoldTime = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset hold-time on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".split-horizon") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.SplitHorizon = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset split-horizon on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".next-hop-self") {
				d.mu.Lock()
				var ic *InterfaceConfig
				if c, exists := inst.configuredInterfaces[ifName]; exists {
					c.NextHopSelf = nil
					ic = c
				}
				d.mu.Unlock()
				if ic != nil {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Reset next-hop-self on interface to default")
				go d.CollectAndPublish(context.Background())
				return
			}

			// Full interface deletion
			d.mu.Lock()
			delete(inst.configuredInterfaces, ifName)
			delete(inst.configuredInterfaces, normalizeIfName(ifName))
			for k := range inst.configuredInterfaces {
				if normalizeIfName(k) == normalizeIfName(ifName) {
					delete(inst.configuredInterfaces, k)
				}
			}
			normIf := normalizeIfName(ifName)
			for nbrIP, nbr := range inst.neighbors {
				if normalizeIfName(nbr.Interface) == normIf {
					delete(inst.neighbors, nbrIP)
				}
			}
			for i, intf := range inst.interfaces {
				if normalizeIfName(intf.Name) == normIf || intf.InterfaceName == normIf {
					delete(inst.interfaces, i)
				}
			}
			for tfIf := range inst.traffic {
				if normalizeIfName(tfIf) == normIf {
					delete(inst.traffic, tfIf)
				}
			}
			d.mu.Unlock()
			C.srlShimInterfaceDisable(cNetinst, cIfname)
			C.srlShimInterfaceDisableV6(cNetinst, cIfname)
			log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Disabled EIGRP on deleted interface")
			go d.CollectAndPublish(context.Background())
			return
		}

		if strings.Contains(jsPath, ".summary-address") {
			pfx := extractSummaryPrefix(cfg)
			d.mu.Lock()
			ic := inst.configuredInterfaces[ifName]
			if ic == nil {
				ic = &InterfaceConfig{InterfaceName: ifName, AdminState: "enable"}
				inst.configuredInterfaces[ifName] = ic
			}
			var saCfg SummaryAddressConfig
			if err := json.Unmarshal([]byte(jsonStr), &saCfg); err != nil && strings.Contains(jsPath, ".distance") {
				var dist uint8
				if err2 := json.Unmarshal([]byte(jsonStr), &dist); err2 == nil {
					saCfg.Distance = dist
				}
			}
			if saCfg.Prefix == "" && pfx != "" {
				saCfg.Prefix = pfx
			}
			if saCfg.Distance == 0 {
				saCfg.Distance = 5
			}
			found := false
			for i, existing := range ic.SummaryAddress {
				if existing.Prefix == saCfg.Prefix {
					ic.SummaryAddress[i] = saCfg
					found = true
					break
				}
			}
			if !found && saCfg.Prefix != "" {
				ic.SummaryAddress = append(ic.SummaryAddress, saCfg)
			}
			d.mu.Unlock()
			d.applyInterface(inst, ic)
			log.Info().Str("netinst", netinst).Str("interface", ifName).Interface("summary_address", saCfg).Msg("Configured summary-address on interface")
			go d.CollectAndPublish(context.Background())
			return
		}

		d.mu.Lock()
		ic, exists := inst.configuredInterfaces[ifName]
		if !exists || ic == nil {
			ic = &InterfaceConfig{InterfaceName: ifName, AdminState: "enable"}
			inst.configuredInterfaces[ifName] = ic
		}

		if strings.Contains(jsPath, ".admin-state") {
			var s string
			if err := json.Unmarshal([]byte(jsonStr), &s); err == nil && s != "" {
				ic.AdminState = s
			} else {
				var leaf struct {
					AdminState string `json:"admin-state"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.AdminState != "" {
					ic.AdminState = leaf.AdminState
				}
			}
		} else if strings.Contains(jsPath, ".delay") {
			var dVal uint32
			if err := json.Unmarshal([]byte(jsonStr), &dVal); err == nil {
				ic.Delay = &dVal
			} else {
				var leaf struct {
					Delay uint32 `json:"delay"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.Delay = &leaf.Delay
				}
			}
		} else if strings.Contains(jsPath, ".bandwidth-percent") || strings.Contains(jsPath, ".bandwidth_percent") {
			var bpVal uint32
			if err := json.Unmarshal([]byte(jsonStr), &bpVal); err == nil && bpVal > 0 {
				ic.BandwidthPercent = &bpVal
			} else {
				var leaf struct {
					BandwidthPercent uint32 `json:"bandwidth-percent"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil && leaf.BandwidthPercent > 0 {
					ic.BandwidthPercent = &leaf.BandwidthPercent
				}
			}
		} else if strings.Contains(jsPath, ".bandwidth") {
			var bVal uint32
			if err := json.Unmarshal([]byte(jsonStr), &bVal); err == nil {
				ic.Bandwidth = &bVal
			} else {
				var leaf struct {
					Bandwidth uint32 `json:"bandwidth"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.Bandwidth = &leaf.Bandwidth
				}
			}
		} else if strings.Contains(jsPath, ".passive") {
			var pVal bool
			if err := json.Unmarshal([]byte(jsonStr), &pVal); err == nil {
				ic.Passive = &pVal
			} else {
				var leaf struct {
					Passive bool `json:"passive"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.Passive = &leaf.Passive
				}
			}
		} else if strings.Contains(jsPath, ".hello-interval") {
			var hVal uint16
			if err := json.Unmarshal([]byte(jsonStr), &hVal); err == nil {
				ic.HelloInterval = &hVal
			} else {
				var leaf struct {
					HelloInterval uint16 `json:"hello-interval"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.HelloInterval = &leaf.HelloInterval
				}
			}
		} else if strings.Contains(jsPath, ".hold-time") {
			var hVal uint16
			if err := json.Unmarshal([]byte(jsonStr), &hVal); err == nil {
				ic.HoldTime = &hVal
			} else {
				var leaf struct {
					HoldTime uint16 `json:"hold-time"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.HoldTime = &leaf.HoldTime
				}
			}
		} else if strings.Contains(jsPath, ".split-horizon") {
			var shVal bool
			if err := json.Unmarshal([]byte(jsonStr), &shVal); err == nil {
				ic.SplitHorizon = &shVal
			} else {
				var leaf struct {
					SplitHorizon bool `json:"split-horizon"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.SplitHorizon = &leaf.SplitHorizon
				}
			}
		} else if strings.Contains(jsPath, ".next-hop-self") {
			var nhsVal bool
			if err := json.Unmarshal([]byte(jsonStr), &nhsVal); err == nil {
				ic.NextHopSelf = &nhsVal
			} else {
				var leaf struct {
					NextHopSelf bool `json:"next-hop-self"`
				}
				if err := json.Unmarshal([]byte(jsonStr), &leaf); err == nil {
					ic.NextHopSelf = &leaf.NextHopSelf
				}
			}
		} else if strings.Contains(jsPath, ".authentication") {
			var authCfg AuthConfig
			if err := json.Unmarshal([]byte(jsonStr), &authCfg); err == nil && (authCfg.Mode != "" || authCfg.Keychain != "" || authCfg.AuthenticationKey != "" || authCfg.AdminState != "") {
				ic.Authentication = &authCfg
			} else {
				cur := ic.Authentication
				var newAuth AuthConfig
				if cur != nil {
					newAuth = *cur
				}
				if strings.Contains(jsPath, ".mode") {
					var m string
					if err := json.Unmarshal([]byte(jsonStr), &m); err == nil {
						newAuth.Mode = m
						ic.Authentication = &newAuth
					}
				} else if strings.Contains(jsPath, ".keychain") {
					var kc string
					if err := json.Unmarshal([]byte(jsonStr), &kc); err == nil {
						newAuth.Keychain = kc
						ic.Authentication = &newAuth
					}
				} else if strings.Contains(jsPath, ".authentication-key") || strings.Contains(jsPath, ".authentication_key") {
					var k string
					if err := json.Unmarshal([]byte(jsonStr), &k); err == nil {
						newAuth.AuthenticationKey = k
						ic.Authentication = &newAuth
					}
				} else if strings.Contains(jsPath, ".admin-state") {
					var s string
					if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
						newAuth.AdminState = s
						ic.Authentication = &newAuth
					}
				}
			}
		} else if strings.Contains(jsPath, ".bfd") {
			var bfdCfg BfdConfig
			if err := json.Unmarshal([]byte(jsonStr), &bfdCfg); err == nil && (bfdCfg.AdminState != "" || bfdCfg.DesiredMinimumTxInterval != nil || bfdCfg.RequiredMinimumReceive != nil || bfdCfg.DetectionMultiplier != nil) {
				ic.Bfd = &bfdCfg
			} else {
				cur := ic.Bfd
				var newBfd BfdConfig
				if cur != nil {
					newBfd = *cur
				}
				if strings.Contains(jsPath, ".admin-state") {
					var s string
					if err := json.Unmarshal([]byte(jsonStr), &s); err == nil {
						newBfd.AdminState = s
						ic.Bfd = &newBfd
					}
				} else if strings.Contains(jsPath, ".desired-minimum-tx-interval") {
					var v uint32
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.DesiredMinimumTxInterval = &v
						ic.Bfd = &newBfd
					}
				} else if strings.Contains(jsPath, ".required-minimum-receive") {
					var v uint32
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.RequiredMinimumReceive = &v
						ic.Bfd = &newBfd
					}
				} else if strings.Contains(jsPath, ".detection-multiplier") {
					var v uint8
					if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
						newBfd.DetectionMultiplier = &v
						ic.Bfd = &newBfd
					}
				}
			}
		} else {
			var parsed InterfaceConfig
			if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
				parsed.InterfaceName = ifName
				if parsed.AdminState != "" {
					ic.AdminState = parsed.AdminState
				} else {
					ic.AdminState = "enable"
				}
				ic.Passive = parsed.Passive
				ic.HelloInterval = parsed.HelloInterval
				ic.HoldTime = parsed.HoldTime
				ic.SplitHorizon = parsed.SplitHorizon
				ic.NextHopSelf = parsed.NextHopSelf
				ic.Bandwidth = parsed.Bandwidth
				ic.BandwidthPercent = parsed.BandwidthPercent
				ic.Delay = parsed.Delay
				ic.Authentication = parsed.Authentication
				ic.Bfd = parsed.Bfd
				if len(parsed.SummaryAddress) > 0 {
					ic.SummaryAddress = parsed.SummaryAddress
				}
				if len(parsed.AddressFamily) > 0 {
					ic.AddressFamily = parsed.AddressFamily
				}
			}
		}
		if ic.AdminState == "" {
			ic.AdminState = "enable"
		}
		d.mu.Unlock()
		d.applyInterface(inst, ic)
		log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Configured EIGRP on interface")
		go d.CollectAndPublish(context.Background())
		return
	}

	// 8c. Handle sub-path protocol-level address-family notification
	if strings.Contains(jsPath, ".protocols.eigrp.address-family") && !strings.Contains(jsPath, ".interface") {
		inst := d.GetOrCreateInstance(netinst)
		cNetinst := C.CString(netinst)
		defer C.free(unsafe.Pointer(cNetinst))

		afName := extractAfName(cfg)
		log.Info().Str("netinst", netinst).Str("af", afName).Str("op", op.String()).Str("json", jsonStr).Msg("Handling protocol address-family notification")

		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if strings.Contains(jsPath, ".export-policy") {
				d.mu.Lock()
				inst.SetAfiExportPolicy(afName, "")
				d.mu.Unlock()
				d.TriggerRedistSync(netinst)
			} else if strings.Contains(jsPath, ".import-policy") {
				d.mu.Lock()
				inst.SetAfiImportPolicy(afName, "")
				d.mu.Unlock()
			} else if strings.Contains(jsPath, ".traffic-share-balanced") || strings.Contains(jsPath, ".traffic_share_balanced") {
				d.mu.Lock()
				inst.SetAfiTrafficShareBalanced(afName, nil)
				d.mu.Unlock()
				d.applyInstanceFeatures(inst)
			} else if strings.Contains(jsPath, ".auto-summary") || strings.Contains(jsPath, ".auto_summary") {
				d.mu.Lock()
				inst.SetAfiAutoSummary(afName, nil)
				d.mu.Unlock()
				d.applyInstanceFeatures(inst)
			} else if strings.Contains(jsPath, ".default-metric") || strings.Contains(jsPath, ".default_metric") {
				d.mu.Lock()
				inst.SetAfiDefaultMetric(afName, nil)
				d.mu.Unlock()
				d.applyInstanceFeatures(inst)
				d.TriggerRedistSync(netinst)
			} else if strings.Contains(jsPath, ".maximum-prefix") || strings.Contains(jsPath, ".maximum_prefix") {
				d.mu.Lock()
				cur := inst.GetAfiMaximumPrefix(afName)
				if strings.Contains(jsPath, ".warning-only") || strings.Contains(jsPath, ".warning_only") {
					if cur != nil {
						c := *cur
						c.WarningOnly = nil
						inst.SetAfiMaximumPrefix(afName, &c)
					}
				} else if strings.Contains(jsPath, ".threshold") {
					if cur != nil {
						c := *cur
						c.Threshold = 75
						inst.SetAfiMaximumPrefix(afName, &c)
					}
				} else {
					inst.SetAfiMaximumPrefix(afName, nil)
				}
				d.mu.Unlock()
				d.applyInstanceFeatures(inst)
			} else if strings.Contains(jsPath, ".preference") {
				d.mu.Lock()
				inst.SetAfiPreference(afName, 0)
				intPref := inst.preference
				if intPref == 0 {
					intPref = 90
				}
				extPref := inst.GetAfiExternalPreference(afName)
				d.mu.Unlock()
				cAfName := C.CString(afName)
				C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(intPref), C.uint8_t(extPref))
				C.free(unsafe.Pointer(cAfName))
			} else if strings.Contains(jsPath, ".external-preference") || strings.Contains(jsPath, ".external_preference") {
				d.mu.Lock()
				inst.SetAfiExternalPreference(afName, 0)
				extPref := inst.externalPreference
				if extPref == 0 {
					extPref = 170
				}
				intPref := inst.GetAfiPreference(afName)
				d.mu.Unlock()
				cAfName := C.CString(afName)
				C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(intPref), C.uint8_t(extPref))
				C.free(unsafe.Pointer(cAfName))
			} else if strings.Contains(jsPath, ".admin-state") {
				d.mu.Lock()
				inst.SetAfiAdminState(afName, "enable")
				d.mu.Unlock()
				if inst.asn > 0 {
					cRouterId := C.CString(inst.routerId)
					if afName == "ipv6-unicast" {
						C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
					} else if afName == "ipv4-unicast" {
						C.srlShimInstanceCreate(cNetinst, C.uint16_t(inst.asn), cRouterId)
					}
					C.free(unsafe.Pointer(cRouterId))
				}
				d.reapplyInstanceRuntimeConfig(inst)
			} else {
				d.mu.Lock()
				var newAf []AddressFamilyConfig
				for _, af := range inst.addressFamily {
					if af.Name != afName {
						newAf = append(newAf, af)
					}
				}
				inst.addressFamily = newAf
				intPref := inst.GetAfiPreference(afName)
				extPref := inst.GetAfiExternalPreference(afName)
				d.mu.Unlock()

				if inst.asn > 0 && inst.adminState != "disable" {
					cRouterId := C.CString(inst.routerId)
					if afName == "ipv6-unicast" && inst.IsAfiEnabled("ipv6-unicast") {
						C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
					} else if afName == "ipv4-unicast" && inst.IsAfiEnabled("ipv4-unicast") {
						C.srlShimInstanceCreate(cNetinst, C.uint16_t(inst.asn), cRouterId)
					}
					C.free(unsafe.Pointer(cRouterId))
				}
				cAfName := C.CString(afName)
				C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(intPref), C.uint8_t(extPref))
				C.free(unsafe.Pointer(cAfName))
				d.reapplyInstanceRuntimeConfig(inst)
			}
			d.mu.RLock()
			allIntfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
			for _, ic := range inst.configuredInterfaces {
				allIntfs = append(allIntfs, ic)
			}
			d.mu.RUnlock()
			for _, ic := range allIntfs {
				d.applyInterface(inst, ic)
			}
			go d.CollectAndPublish(context.Background())
			return
		}

		var afCfg AddressFamilyConfig
		isContainerUpdate := false
		if err := json.Unmarshal([]byte(jsonStr), &afCfg); err == nil {
			isContainerUpdate = !strings.Contains(jsPath, ".admin-state") &&
				!strings.Contains(jsPath, ".preference") &&
				!strings.Contains(jsPath, ".external-preference") &&
				!strings.Contains(jsPath, ".external_preference") &&
				!strings.Contains(jsPath, ".export-policy") &&
				!strings.Contains(jsPath, ".import-policy") &&
				!strings.Contains(jsPath, ".traffic-share-balanced") &&
				!strings.Contains(jsPath, ".auto-summary") &&
				!strings.Contains(jsPath, ".default-metric") &&
				!strings.Contains(jsPath, ".maximum-prefix")
		} else {
			if strings.Contains(jsPath, ".admin-state") {
				var s string
				if err2 := json.Unmarshal([]byte(jsonStr), &s); err2 == nil {
					afCfg.Name = afName
					afCfg.AdminState = s
				}
			} else if strings.Contains(jsPath, ".preference") {
				var p uint8
				if err2 := json.Unmarshal([]byte(jsonStr), &p); err2 == nil {
					afCfg.Name = afName
					afCfg.Preference = p
				}
			} else if strings.Contains(jsPath, ".external-preference") || strings.Contains(jsPath, ".external_preference") {
				var p uint8
				if err2 := json.Unmarshal([]byte(jsonStr), &p); err2 == nil {
					afCfg.Name = afName
					afCfg.ExternalPreference = p
				}
			} else if strings.Contains(jsPath, ".export-policy") {
				var s string
				if err2 := json.Unmarshal([]byte(jsonStr), &s); err2 == nil {
					afCfg.Name = afName
					afCfg.ExportPolicy = s
				}
			} else if strings.Contains(jsPath, ".import-policy") {
				var s string
				if err2 := json.Unmarshal([]byte(jsonStr), &s); err2 == nil {
					afCfg.Name = afName
					afCfg.ImportPolicy = s
				}
			} else if strings.Contains(jsPath, ".traffic-share-balanced") || strings.Contains(jsPath, ".traffic_share_balanced") {
				var b bool
				if err2 := json.Unmarshal([]byte(jsonStr), &b); err2 == nil {
					afCfg.Name = afName
					afCfg.TrafficShareBalanced = &b
				}
			} else if strings.Contains(jsPath, ".auto-summary") || strings.Contains(jsPath, ".auto_summary") {
				var b bool
				if err2 := json.Unmarshal([]byte(jsonStr), &b); err2 == nil {
					afCfg.Name = afName
					afCfg.AutoSummary = &b
				}
			}
		}
		if afCfg.Name == "" {
			afCfg.Name = afName
		}
		if strings.Contains(jsPath, ".default-metric") || strings.Contains(jsPath, ".default_metric") {
			d.mu.Lock()
			var existing *PolicyMetricConfig
			if cur := inst.GetAfiDefaultMetric(afName); cur != nil {
				c := *cur
				existing = &c
			}
			dm := parseDefaultMetricNotif(jsPath, jsonStr, existing)
			if dm != nil {
				inst.SetAfiDefaultMetric(afName, dm)
			}
			d.mu.Unlock()
			if dm != nil {
				d.applyInstanceFeatures(inst)
				d.TriggerRedistSync(netinst)
			}
			go d.CollectAndPublish(context.Background())
			return
		}
		if strings.Contains(jsPath, ".maximum-prefix") || strings.Contains(jsPath, ".maximum_prefix") {
			d.mu.Lock()
			var existing *MaxPrefixConfig
			if cur := inst.GetAfiMaximumPrefix(afName); cur != nil {
				c := *cur
				existing = &c
			}
			mp := parseMaxPrefixNotif(jsPath, jsonStr, existing)
			if mp != nil {
				inst.SetAfiMaximumPrefix(afName, mp)
			}
			d.mu.Unlock()
			if mp != nil {
				d.applyInstanceFeatures(inst)
			}
			go d.CollectAndPublish(context.Background())
			return
		}
		if isContainerUpdate || afCfg.AdminState != "" || afCfg.ExportPolicy != "" || afCfg.ImportPolicy != "" || afCfg.Preference > 0 || afCfg.ExternalPreference > 0 || afCfg.TrafficShareBalanced != nil || afCfg.AutoSummary != nil || afCfg.DefaultMetric != nil || afCfg.MaximumPrefix != nil {
			d.mu.Lock()
			if afCfg.AdminState != "" {
				inst.SetAfiAdminState(afCfg.Name, afCfg.AdminState)
			}
			if isContainerUpdate {
				if afCfg.TrafficShareBalanced != nil && *afCfg.TrafficShareBalanced {
					inst.SetAfiTrafficShareBalanced(afCfg.Name, afCfg.TrafficShareBalanced)
				} else {
					inst.SetAfiTrafficShareBalanced(afCfg.Name, nil)
				}
				if afCfg.AutoSummary != nil && *afCfg.AutoSummary {
					inst.SetAfiAutoSummary(afCfg.Name, afCfg.AutoSummary)
				} else {
					inst.SetAfiAutoSummary(afCfg.Name, nil)
				}
			} else {
				if afCfg.TrafficShareBalanced != nil {
					inst.SetAfiTrafficShareBalanced(afCfg.Name, afCfg.TrafficShareBalanced)
				}
				if afCfg.AutoSummary != nil {
					inst.SetAfiAutoSummary(afCfg.Name, afCfg.AutoSummary)
				}
			}
			if afCfg.DefaultMetric != nil && (!isContainerUpdate || !isDefaultPolicyMetric(afCfg.DefaultMetric)) {
				dmCopy := *afCfg.DefaultMetric
				applyMetricDefaults(&dmCopy)
				inst.SetAfiDefaultMetric(afCfg.Name, &dmCopy)
			} else if isContainerUpdate {
				inst.SetAfiDefaultMetric(afCfg.Name, nil)
			}
			if afCfg.MaximumPrefix != nil && (!isContainerUpdate || afCfg.MaximumPrefix.Limit > 0) {
				mpCopy := *afCfg.MaximumPrefix
				inst.SetAfiMaximumPrefix(afCfg.Name, &mpCopy)
			} else if isContainerUpdate {
				inst.SetAfiMaximumPrefix(afCfg.Name, nil)
			}
			if isContainerUpdate {
				inst.SetAfiExportPolicy(afCfg.Name, afCfg.ExportPolicy)
				inst.SetAfiImportPolicy(afCfg.Name, afCfg.ImportPolicy)
			} else {
				if afCfg.ExportPolicy != "" {
					inst.SetAfiExportPolicy(afCfg.Name, afCfg.ExportPolicy)
				}
				if afCfg.ImportPolicy != "" {
					inst.SetAfiImportPolicy(afCfg.Name, afCfg.ImportPolicy)
				}
			}
			intPref := uint8(0)
			extPref := uint8(0)
			shouldUpdateDist := false
			if afCfg.Preference > 0 || afCfg.ExternalPreference > 0 {
				storePref := afCfg.Preference
				storeExtPref := afCfg.ExternalPreference
				if isContainerUpdate {
					if storePref == 90 {
						storePref = 0
					}
					if storeExtPref == 170 {
						storeExtPref = 0
					}
				}
				inst.SetAfiPreferences(afCfg.Name, storePref, storeExtPref)
				intPref = inst.GetAfiPreference(afCfg.Name)
				extPref = inst.GetAfiExternalPreference(afCfg.Name)
				shouldUpdateDist = true
			}
			d.mu.Unlock()

			if shouldUpdateDist {
				cAfName := C.CString(afCfg.Name)
				C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(intPref), C.uint8_t(extPref))
				C.free(unsafe.Pointer(cAfName))
			}

			if afCfg.AdminState == "disable" {
				if afCfg.Name == "ipv6-unicast" {
					C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
					d.WithdrawAfRoutes(netinst, "ipv6-unicast")
				} else if afCfg.Name == "ipv4-unicast" {
					C.srlShimInstanceDelete(cNetinst)
					d.WithdrawAfRoutes(netinst, "ipv4-unicast")
				}
			} else if afCfg.AdminState == "enable" && inst.asn > 0 {
				cRouterId := C.CString(inst.routerId)
				if afCfg.Name == "ipv6-unicast" {
					C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
				} else if afCfg.Name == "ipv4-unicast" {
					C.srlShimInstanceCreate(cNetinst, C.uint16_t(inst.asn), cRouterId)
				}
				C.free(unsafe.Pointer(cRouterId))
			}

			d.reapplyInstanceRuntimeConfig(inst)
		} else {
			if strings.Contains(jsPath, ".admin-state") {
				var adminStr string
				if err := json.Unmarshal([]byte(jsonStr), &adminStr); err == nil {
					d.mu.Lock()
					inst.SetAfiAdminState(afName, adminStr)
					d.mu.Unlock()
					if adminStr == "disable" {
						if afName == "ipv6-unicast" {
							C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
							d.WithdrawAfRoutes(netinst, "ipv6-unicast")
						} else if afName == "ipv4-unicast" {
							C.srlShimInstanceDelete(cNetinst)
							d.WithdrawAfRoutes(netinst, "ipv4-unicast")
						}
					} else if adminStr == "enable" && inst.asn > 0 {
						cRouterId := C.CString(inst.routerId)
						if afName == "ipv6-unicast" {
							C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
						} else if afName == "ipv4-unicast" {
							C.srlShimInstanceCreate(cNetinst, C.uint16_t(inst.asn), cRouterId)
						}
						C.free(unsafe.Pointer(cRouterId))
					}
					d.reapplyInstanceRuntimeConfig(inst)
				}
			} else if strings.Contains(jsPath, ".preference") {
				var pref uint8
				if err := json.Unmarshal([]byte(jsonStr), &pref); err == nil {
					d.mu.Lock()
					inst.SetAfiPreference(afName, pref)
					extPref := inst.GetAfiExternalPreference(afName)
					d.mu.Unlock()
					cAfName := C.CString(afName)
					C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(pref), C.uint8_t(extPref))
					C.free(unsafe.Pointer(cAfName))
				}
			} else if strings.Contains(jsPath, ".external-preference") || strings.Contains(jsPath, ".external_preference") {
				var extPref uint8
				if err := json.Unmarshal([]byte(jsonStr), &extPref); err == nil {
					d.mu.Lock()
					inst.SetAfiExternalPreference(afName, extPref)
					intPref := inst.GetAfiPreference(afName)
					d.mu.Unlock()
					cAfName := C.CString(afName)
					C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(intPref), C.uint8_t(extPref))
					C.free(unsafe.Pointer(cAfName))
				}
			} else if strings.Contains(jsPath, ".export-policy") || strings.Contains(jsPath, ".export_policy") {
				d.mu.Lock()
				inst.SetAfiExportPolicy(afName, "")
				d.mu.Unlock()
				d.TriggerRedistSync(netinst)
			} else if strings.Contains(jsPath, ".import-policy") || strings.Contains(jsPath, ".import_policy") {
				d.mu.Lock()
				inst.SetAfiImportPolicy(afName, "")
				d.mu.Unlock()
			}
		}
		go d.CollectAndPublish(context.Background())
		return
	}

	if jsonStr == "" && op != ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
		return
	}

	// 9. Handle top-level protocols.eigrp notification
	if !strings.HasSuffix(jsPath, ".protocols.eigrp") {
		return
	}
	var conf EigrpConfig
	if err := json.Unmarshal([]byte(jsonStr), &conf); err != nil || conf.AutonomousSystem == 0 {
		var wrapper struct {
			Eigrp EigrpConfig `json:"eigrp"`
		}
		if errWrap := json.Unmarshal([]byte(jsonStr), &wrapper); errWrap == nil && wrapper.Eigrp.AutonomousSystem != 0 {
			conf = wrapper.Eigrp
		} else if err != nil {
			log.Error().Err(err).Str("json", jsonStr).Msg("Failed to parse EIGRP config JSON")
			return
		}
	}

	d.mu.RLock()
	existingInst := d.instances[netinst]
	d.mu.RUnlock()

	if conf.AutonomousSystem == 0 && existingInst != nil && existingInst.asn > 0 {
		conf.AutonomousSystem = existingInst.asn
		if conf.RouterId == "" {
			conf.RouterId = existingInst.routerId
		}
		if conf.AdminState == "" {
			conf.AdminState = existingInst.adminState
		}
	}

	if conf.AutonomousSystem == 0 && conf.AdminState != "disable" {
		log.Debug().Str("json", jsonStr).Msg("Ignoring config update with no ASN")
		return
	}

	log.Info().
		Str("netinst", netinst).
		Str("admin_state", conf.AdminState).
		Uint16("asn", conf.AutonomousSystem).
		Str("router_id", conf.RouterId).
		Msg("Applying EIGRP Configuration to DUAL Core")

	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	inst := d.GetOrCreateInstance(netinst)
	d.mu.Lock()
	inst.asn = conf.AutonomousSystem
	inst.routerId = conf.RouterId
	if conf.AdminState != "" {
		inst.adminState = conf.AdminState
	} else if inst.adminState == "" {
		inst.adminState = "enable"
	}
	inst.networks = conf.Network
	inst.exportPolicy = conf.ExportPolicy
	inst.importPolicy = conf.ImportPolicy
	if conf.Variance > 0 {
		inst.variance = conf.Variance
	} else {
		inst.variance = 1
	}
	if conf.MaximumPaths > 0 {
		inst.maximumPaths = conf.MaximumPaths
	} else {
		inst.maximumPaths = 4
	}
	if conf.MaximumHops > 0 {
		inst.maximumHops = conf.MaximumHops
	} else {
		inst.maximumHops = 100
	}
	if conf.Preference > 0 {
		inst.preference = conf.Preference
	} else {
		inst.preference = 90
	}
	if conf.ExternalPreference > 0 {
		inst.externalPreference = conf.ExternalPreference
	} else {
		inst.externalPreference = 170
	}
	if conf.Timers != nil {
		inst.timers = conf.Timers
	}
	if conf.Authentication != nil {
		inst.authentication = conf.Authentication
	}
	if conf.Metrics != nil {
		inst.metrics = conf.Metrics
	}
	if conf.MetricWeights != nil {
		inst.metricWeights = conf.MetricWeights
	}
	if len(conf.AddressFamily) > 0 {
		for i := range conf.AddressFamily {
			if conf.AddressFamily[i].TrafficShareBalanced != nil && !*conf.AddressFamily[i].TrafficShareBalanced {
				conf.AddressFamily[i].TrafficShareBalanced = nil
			}
			if conf.AddressFamily[i].AutoSummary != nil && !*conf.AddressFamily[i].AutoSummary {
				conf.AddressFamily[i].AutoSummary = nil
			}
			if conf.AddressFamily[i].DefaultMetric != nil && isDefaultPolicyMetric(conf.AddressFamily[i].DefaultMetric) {
				conf.AddressFamily[i].DefaultMetric = nil
			}
			if conf.AddressFamily[i].MaximumPrefix != nil && conf.AddressFamily[i].MaximumPrefix.Limit == 0 {
				conf.AddressFamily[i].MaximumPrefix = nil
			}
		}
		inst.addressFamily = conf.AddressFamily
	}
	if conf.RibScale != nil && *conf.RibScale > 0 {
		inst.ribScale = *conf.RibScale
	} else if inst.ribScale == 0 {
		inst.ribScale = 128
	}
	if conf.WideMetrics != nil {
		inst.wideMetrics = *conf.WideMetrics
	} else {
		inst.wideMetrics = true
	}
	if conf.TrafficShareBalanced != nil {
		inst.trafficShareBalanced = *conf.TrafficShareBalanced
	} else {
		inst.trafficShareBalanced = false
	}
	if conf.AutoSummary != nil {
		inst.autoSummary = *conf.AutoSummary
	} else {
		inst.autoSummary = false
	}
	if conf.EventLogSize != nil && *conf.EventLogSize > 0 {
		inst.eventLogSize = *conf.EventLogSize
	} else if inst.eventLogSize == 0 {
		inst.eventLogSize = 500
	}
	if conf.DefaultMetric != nil {
		dmCopy := *conf.DefaultMetric
		applyMetricDefaults(&dmCopy)
		inst.defaultMetric = &dmCopy
	} else {
		inst.defaultMetric = nil
	}
	if conf.MaximumPrefix != nil && conf.MaximumPrefix.Limit > 0 {
		mpCopy := *conf.MaximumPrefix
		inst.maximumPrefix = &mpCopy
	} else {
		inst.maximumPrefix = nil
	}
	if conf.GracefulRestart != nil {
		inst.gracefulRestart = conf.GracefulRestart
		if conf.GracefulRestart.AdminState == "disable" {
			inst.restarting = false
		}
	} else {
		inst.gracefulRestart = nil
		inst.restarting = false
	}
	if conf.DefaultInterface != nil {
		if inst.defaultIntf != nil {
			if conf.DefaultInterface.AdminState == "" {
				conf.DefaultInterface.AdminState = inst.defaultIntf.AdminState
			}
			if conf.DefaultInterface.HelloInterval == 0 {
				conf.DefaultInterface.HelloInterval = inst.defaultIntf.HelloInterval
			}
			if conf.DefaultInterface.HoldTime == 0 {
				conf.DefaultInterface.HoldTime = inst.defaultIntf.HoldTime
			}
			if conf.DefaultInterface.SplitHorizon == nil {
				conf.DefaultInterface.SplitHorizon = inst.defaultIntf.SplitHorizon
			}
			if conf.DefaultInterface.NextHopSelf == nil {
				conf.DefaultInterface.NextHopSelf = inst.defaultIntf.NextHopSelf
			}
			if conf.DefaultInterface.Bandwidth == nil {
				conf.DefaultInterface.Bandwidth = inst.defaultIntf.Bandwidth
			}
			if conf.DefaultInterface.BandwidthPercent == nil {
				conf.DefaultInterface.BandwidthPercent = inst.defaultIntf.BandwidthPercent
			}
			if conf.DefaultInterface.Delay == nil {
				conf.DefaultInterface.Delay = inst.defaultIntf.Delay
			}
			if conf.DefaultInterface.Authentication == nil && !strings.Contains(jsonStr, "\"authentication\"") {
				conf.DefaultInterface.Authentication = inst.defaultIntf.Authentication
			}
			if conf.DefaultInterface.Bfd == nil && !strings.Contains(jsonStr, "\"bfd\"") {
				conf.DefaultInterface.Bfd = inst.defaultIntf.Bfd
			}
			if len(conf.DefaultInterface.AddressFamily) == 0 && len(inst.defaultIntf.AddressFamily) > 0 {
				conf.DefaultInterface.AddressFamily = inst.defaultIntf.AddressFamily
			}
		}
		inst.defaultIntf = conf.DefaultInterface
	} else if inst.defaultIntf == nil {
		inst.defaultIntf = &DefaultInterfaceConfig{
			AdminState:    "enable",
			Passive:       false,
			HelloInterval: 5,
			HoldTime:      15,
		}
	}
	d.mu.Unlock()

	if conf.AdminState == "disable" {
		d.mu.Lock()
		inst.operState = "down"
		inst.routes = make(map[string]*RouteInfo)
		inst.neighbors = make(map[string]*NeighborInfo)
		inst.topology = make(map[string]*TopologyPrefixInfo)
		inst.interfaces = make(map[string]*InterfaceInfo)
		inst.traffic = make(map[string]*TrafficInfo)
		for _, ifcfg := range conf.Interface {
			if ifcfg.InterfaceName != "" {
				cfgCopy := ifcfg
				inst.configuredInterfaces[ifcfg.InterfaceName] = &cfgCopy
			}
		}
		for _, sn := range conf.StaticNeighbor {
			if sn.IPAddress != "" {
				cfgCopy := sn
				inst.staticNeighbors[sn.IPAddress] = &cfgCopy
			}
		}
		d.mu.Unlock()
		C.srlShimInstanceDelete(cNetinst)
		C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
		log.Info().Str("netinst", netinst).Msg("EIGRP instance disabled")
		go d.CollectAndPublish(context.Background())
		return
	}

	if conf.AutonomousSystem > 0 {
		cRouterId := C.CString(conf.RouterId)
		if inst.IsAfiEnabled("ipv4-unicast") {
			res := C.srlShimInstanceCreate(cNetinst, C.uint16_t(conf.AutonomousSystem), cRouterId)
			if res != 0 {
				log.Error().Str("netinst", netinst).Uint16("asn", conf.AutonomousSystem).Msg("Failed to create IPv4 EIGRP instance")
			} else {
				log.Info().Str("netinst", netinst).Uint16("asn", conf.AutonomousSystem).Msg("Created IPv4 EIGRP instance")
			}
		} else {
			C.srlShimInstanceDelete(cNetinst)
			d.WithdrawAfRoutes(netinst, "ipv4-unicast")
			log.Info().Str("netinst", netinst).Msg("Disabled IPv4 EIGRP instance")
		}

		if inst.IsAfiEnabled("ipv6-unicast") {
			v6Res := C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(conf.AutonomousSystem), cRouterId)
			if v6Res != 0 {
				log.Error().Str("netinst", netinst).Uint16("asn", conf.AutonomousSystem).Msg("Failed to create IPv6 EIGRP instance")
			} else {
				log.Info().Str("netinst", netinst).Uint16("asn", conf.AutonomousSystem).Msg("Created IPv6 EIGRP instance")
			}
		} else {
			C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(conf.AutonomousSystem))
			d.WithdrawAfRoutes(netinst, "ipv6-unicast")
			log.Info().Str("netinst", netinst).Msg("Disabled IPv6 EIGRP instance")
		}
		C.free(unsafe.Pointer(cRouterId))

		// Apply rib-scale
		C.srl_set_rib_scale(cNetinst, C.uint8_t(inst.ribScale))

		// Apply metrics
		metrics := conf.Metrics
		if metrics == nil {
			metrics = conf.MetricWeights
		}
		d.mu.Lock()
		inst.metrics = metrics
		scale := inst.ribScale
		wm := inst.wideMetrics
		d.mu.Unlock()
		d.applyMetrics(netinst, metrics, scale, wm)

		// Apply graceful restart
		d.applyGracefulRestart(netinst, inst.gracefulRestart)

		// Apply upstream instance features
		d.applyInstanceFeatures(inst)

		if len(conf.StaticNeighbor) > 0 {
			var toApply []*StaticNeighborConfig
			d.mu.Lock()
			for _, sn := range conf.StaticNeighbor {
				if sn.IPAddress != "" {
					cfgCopy := sn
					inst.staticNeighbors[sn.IPAddress] = &cfgCopy
					toApply = append(toApply, &cfgCopy)
				}
			}
			d.mu.Unlock()
			for _, sn := range toApply {
				d.applyStaticNeighbor(netinst, sn)
			}
		}

		// Apply interfaces from top-level config
		for _, ifcfg := range conf.Interface {
			if ifcfg.InterfaceName == "" {
				continue
			}
			cfgCopy := ifcfg
			d.mu.Lock()
			if existing, ok := inst.configuredInterfaces[ifcfg.InterfaceName]; ok && existing != nil {
				if len(cfgCopy.AddressFamily) == 0 && len(existing.AddressFamily) > 0 {
					cfgCopy.AddressFamily = existing.AddressFamily
				}
				if len(cfgCopy.SummaryAddress) == 0 && len(existing.SummaryAddress) > 0 {
					cfgCopy.SummaryAddress = existing.SummaryAddress
				}
			}
			inst.configuredInterfaces[ifcfg.InterfaceName] = &cfgCopy
			d.mu.Unlock()
			d.applyInterface(inst, &cfgCopy)
		}

		// Re-apply all configured interfaces to inherit updated default-interface settings
		d.mu.RLock()
		allIntfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
		for _, ic := range inst.configuredInterfaces {
			allIntfs = append(allIntfs, ic)
		}
		d.mu.RUnlock()
		for _, ic := range allIntfs {
			d.applyInterface(inst, ic)
		}

		// Apply legacy networks
		for _, pfx := range conf.Network {
			pfx = strings.TrimSpace(pfx)
			if pfx == "" {
				continue
			}
			cPfx := C.CString(pfx)
			netRes := C.srlShimNetworkAdd(cNetinst, cPfx)
			C.free(unsafe.Pointer(cPfx))
			if netRes != 0 {
				log.Warn().Str("prefix", pfx).Msg("Failed to add network prefix to EIGRP")
			} else {
				log.Info().Str("prefix", pfx).Msg("Added network prefix to EIGRP")
			}
		}

		// Apply redistribution policy
		d.applyRedistribute(netinst, inst.exportPolicy)

		varVar := conf.Variance
		if varVar == 0 {
			varVar = 1
		}
		C.srlShimVarianceUpdate(cNetinst, C.uint8_t(varVar))
		if varVar > 1 {
			log.Info().Str("netinst", netinst).Uint8("variance", varVar).Msg("EIGRP variance > 1 configured: feasible successor routes within variance window are installed into FIB as uniform ECMP multipath due to NDK schema boundaries")
		}

		maxPaths := conf.MaximumPaths
		if maxPaths == 0 {
			maxPaths = 4
		}
		C.srlShimMaxPathsUpdate(cNetinst, C.uint8_t(maxPaths))

		maxHops := conf.MaximumHops
		if maxHops == 0 {
			maxHops = 100
		}
		C.srlShimMaxHopsUpdate(cNetinst, C.uint8_t(maxHops))
		if conf.Timers != nil {
			d.applyTimers(netinst, conf.Timers)
		}

		// Apply distance / preference
		intDist := inst.preference
		if intDist == 0 {
			intDist = 90
		}
		extDist := inst.externalPreference
		if extDist == 0 {
			extDist = 170
		}
		C.srlShimDistanceUpdate(cNetinst, C.uint8_t(intDist), C.uint8_t(extDist))
		for _, af := range inst.addressFamily {
			afInt := af.Preference
			if afInt == 0 {
				afInt = intDist
			}
			afExt := af.ExternalPreference
			if afExt == 0 {
				afExt = extDist
			}
			cAfName := C.CString(af.Name)
			C.srlShimDistanceUpdateAfi(cNetinst, cAfName, C.uint8_t(afInt), C.uint8_t(afExt))
			C.free(unsafe.Pointer(cAfName))
		}

		go d.CollectAndPublish(context.Background())
	}
}

func parseCandidateNextHop(nhStr string) string {
	nhStr = strings.TrimSpace(nhStr)
	if nhStr == "" || strings.EqualFold(nhStr, "direct") {
		return ""
	}
	if idx := strings.Index(nhStr, "("); idx != -1 {
		nhStr = nhStr[:idx]
	}
	if idx := strings.Index(nhStr, ","); idx != -1 {
		nhStr = nhStr[:idx]
	}
	ip := net.ParseIP(strings.TrimSpace(nhStr))
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func matchProtocol(policyProto, routeType, routeOwner string, isV6 bool) bool {
	pProto := strings.ToLower(strings.TrimSpace(policyProto))
	if idx := strings.Index(pProto, ":"); idx != -1 {
		pProto = pProto[idx+1:]
	}
	rType := strings.ToLower(strings.TrimSpace(routeType))
	rOwner := strings.ToLower(strings.TrimSpace(routeOwner))
	if pProto == "" {
		return true
	}

	normOwner := strings.TrimSuffix(rOwner, "_mgr")
	normOwner = strings.TrimSuffix(normOwner, "_route")

	matchesOspf := strings.Contains(rType, "ospf") || strings.Contains(normOwner, "ospf")
	matchesOspfv2 := strings.Contains(rType, "ospfv2") || strings.Contains(rType, "ospf-v2") || (matchesOspf && !isV6)
	matchesOspfv3 := strings.Contains(rType, "ospfv3") || strings.Contains(rType, "ospf-v3") || strings.Contains(rType, "ospf3") || (matchesOspf && isV6)
	matchesBgp := strings.Contains(rType, "bgp") || strings.Contains(normOwner, "bgp")
	matchesIsis := strings.Contains(rType, "isis") || strings.Contains(rType, "is-is") || strings.Contains(normOwner, "isis") || strings.Contains(normOwner, "is-is")
	matchesStatic := strings.Contains(rType, "static") || strings.Contains(normOwner, "static")
	matchesLocal := strings.Contains(rType, "local") || strings.Contains(rType, "connected") || strings.Contains(rType, "host") || strings.Contains(normOwner, "local") || strings.Contains(normOwner, "net_inst")

	switch pProto {
	case "ospf":
		return matchesOspf
	case "ospfv2", "ospf-v2":
		return matchesOspfv2
	case "ospfv3", "ospf-v3", "ospf3":
		return matchesOspfv3
	case "bgp":
		return matchesBgp
	case "isis", "is-is":
		return matchesIsis
	case "static":
		return matchesStatic
	case "local", "connected":
		return matchesLocal
	default:
		return pProto == rType || pProto == normOwner
	}
}

func normalizeRedistProtocol(routeType, routeOwner string, isV6 bool) string {
	rType := strings.ToLower(strings.TrimSpace(routeType))
	rOwner := strings.ToLower(strings.TrimSpace(routeOwner))
	if strings.Contains(rType, "ospf") || strings.Contains(rOwner, "ospf") {
		return "ospf"
	}
	if strings.Contains(rType, "bgp") || strings.Contains(rOwner, "bgp") {
		return "bgp"
	}
	if strings.Contains(rType, "isis") || strings.Contains(rType, "is-is") || strings.Contains(rOwner, "isis") || strings.Contains(rOwner, "is-is") {
		return "isis"
	}
	if strings.Contains(rType, "static") || strings.Contains(rOwner, "static") {
		return "static"
	}
	if strings.Contains(rType, "local") || strings.Contains(rType, "connected") || strings.Contains(rType, "host") || strings.Contains(rOwner, "local") || strings.Contains(rOwner, "net_inst") {
		return "connected"
	}
	if rType != "" {
		return rType
	}
	return "static"
}

type candidateRouteCacheEntry struct {
	routes    []CandidateRoute
	timestamp time.Time
	dirty     bool
}

const candidateRouteCacheTTL = 3 * time.Second

func (d *EigrpDaemon) InvalidateCandidateRouteCache(netinst string) {
	d.routeCacheMu.Lock()
	defer d.routeCacheMu.Unlock()
	if d.routeCache == nil {
		return
	}
	if netinst == "" || netinst == "*" || netinst == "all" {
		for _, entry := range d.routeCache {
			entry.dirty = true
		}
		return
	}
	prefix := netinst + ":"
	for k, entry := range d.routeCache {
		if strings.HasPrefix(k, prefix) {
			entry.dirty = true
		}
	}
}

func (d *EigrpDaemon) GetCandidateRoutes(netinst string, afi string) ([]CandidateRoute, error) {
	if netinst == "" {
		netinst = "default"
	}
	resolved := d.resolveNetinstName(netinst)
	isV6 := strings.Contains(afi, "v6") || strings.Contains(afi, "6")
	d.candidateMu.RLock()
	instRoutes := d.candidateRoutes[resolved]
	if len(instRoutes) == 0 && resolved != netinst {
		instRoutes = d.candidateRoutes[netinst]
	}
	if len(instRoutes) == 0 {
		if idStr, ok := d.getNetinstId(resolved); ok && idStr != "" {
			instRoutes = d.candidateRoutes[idStr]
		}
	}
	if len(instRoutes) > 0 {
		res := make([]CandidateRoute, 0, len(instRoutes))
		for pfx, cr := range instRoutes {
			pfxV6 := strings.Contains(pfx, ":")
			if isV6 == pfxV6 {
				if cr.RouteOwner == "" && cr.OwnerId != 0 {
					cr.RouteOwner = d.getAppOwner(cr.OwnerId)
					if cr.RouteOwner != "" {
						cr.RouteType = cr.RouteOwner
					}
				}
				res = append(res, cr)
			}
		}
		d.candidateMu.RUnlock()
		return res, nil
	}
	d.candidateMu.RUnlock()

	cacheKey := netinst + ":" + afi
	d.routeCacheMu.RLock()
	defer d.routeCacheMu.RUnlock()
	if d.routeCache != nil {
		if entry, exists := d.routeCache[cacheKey]; exists && entry != nil && !entry.dirty && time.Since(entry.timestamp) < candidateRouteCacheTTL {
			routes := make([]CandidateRoute, len(entry.routes))
			copy(routes, entry.routes)
			return routes, nil
		}
	}
	return nil, nil
}

func getCandidateRoutes(netinst string, afi string) ([]CandidateRoute, error) {
	if netinst == "" {
		netinst = "default"
	}
	if daemonApp != nil {
		return daemonApp.GetCandidateRoutes(netinst, afi)
	}
	return nil, nil
}

func (d *EigrpDaemon) resetGNMIClient() {
	d.gnmiMu.Lock()
	defer d.gnmiMu.Unlock()
	if d.gnmiConn != nil {
		_ = d.gnmiConn.Close()
		d.gnmiConn = nil
	}
	d.gnmiClient = nil
}

func (d *EigrpDaemon) getGNMIClient() (gnmi.GNMIClient, error) {
	d.gnmiMu.Lock()
	defer d.gnmiMu.Unlock()
	if d.gnmiClient != nil {
		return d.gnmiClient, nil
	}

	type gnmiDialCandidate struct {
		target  string
		useAuth bool
		user    string
		pass    string
		desc    string
	}

	envUser := os.Getenv("SRL_GNMI_USER")
	envPass := os.Getenv("SRL_GNMI_PASS")
	hasEnv := envUser != "" || envPass != ""

	var ipcTargets []string
	var tcpTargets []string

	if custom := os.Getenv("SRL_GNMI_TARGET"); custom != "" {
		if strings.HasPrefix(custom, "unix://") {
			ipcTargets = append(ipcTargets, custom)
		} else {
			tcpTargets = append(tcpTargets, custom)
		}
	}

	ipcTargets = append(ipcTargets,
		"unix:///opt/srlinux/var/run/sr_grpc_server_insecure-mgmt",
		"unix:///opt/srlinux/var/run/sr_grpc_server_mgmt",
	)

	tcpTargets = append(tcpTargets,
		"127.0.0.1:57401",
		"127.0.0.1:57411",
		"127.0.0.1:57400",
	)

	var candidates []gnmiDialCandidate

	// 1. Prefer IPC over socket without credentials
	for _, t := range ipcTargets {
		candidates = append(candidates, gnmiDialCandidate{
			target:  t,
			useAuth: false,
			desc:    "IPC unix socket without auth metadata",
		})
	}

	// 2. Fall back to socket (TCP) without credentials
	for _, t := range tcpTargets {
		candidates = append(candidates, gnmiDialCandidate{
			target:  t,
			useAuth: false,
			desc:    "network socket (TCP) without auth metadata",
		})
	}

	// 3. Fall back to environment credentials (IPC first, then socket)
	if hasEnv {
		for _, t := range ipcTargets {
			candidates = append(candidates, gnmiDialCandidate{
				target:  t,
				useAuth: true,
				user:    envUser,
				pass:    envPass,
				desc:    "IPC unix socket with environment credentials",
			})
		}
		for _, t := range tcpTargets {
			candidates = append(candidates, gnmiDialCandidate{
				target:  t,
				useAuth: true,
				user:    envUser,
				pass:    envPass,
				desc:    "network socket (TCP) with environment credentials",
			})
		}
	}

	// 4. Fall back to default credentials (IPC first, then socket)
	for _, t := range ipcTargets {
		candidates = append(candidates, gnmiDialCandidate{
			target:  t,
			useAuth: true,
			user:    "admin",
			pass:    "NokiaSrl1!",
			desc:    "IPC unix socket with default credentials",
		})
	}
	for _, t := range tcpTargets {
		candidates = append(candidates, gnmiDialCandidate{
			target:  t,
			useAuth: true,
			user:    "admin",
			pass:    "NokiaSrl1!",
			desc:    "network socket (TCP) with default credentials",
		})
	}

	var lastErr error
	for _, c := range candidates {
		if strings.HasPrefix(c.target, "unix://") {
			sockPath := strings.TrimPrefix(c.target, "unix://")
			if _, statErr := os.Stat(sockPath); statErr != nil {
				continue
			}
		} else {
			probeConn, probeErr := net.DialTimeout("tcp", c.target, 100*time.Millisecond)
			if probeErr != nil {
				lastErr = probeErr
				continue
			}
			_ = probeConn.Close()
		}

		dialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		}
		if c.useAuth {
			user := c.user
			pass := c.pass
			authInterceptor := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				ctx = metadata.AppendToOutgoingContext(ctx, "username", user, "password", pass)
				return invoker(ctx, method, req, reply, cc, opts...)
			}
			dialOpts = append(dialOpts, grpc.WithUnaryInterceptor(authInterceptor))
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := grpc.DialContext(ctx, c.target, dialOpts...)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}

		testClient := gnmi.NewGNMIClient(conn)
		capCtx, capCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, capErr := testClient.Capabilities(capCtx, &gnmi.CapabilityRequest{})
		capCancel()
		if capErr != nil {
			st := status.Code(capErr)
			if st == codes.Unauthenticated || st == codes.PermissionDenied {
				log.Debug().Str("target", c.target).Str("strategy", c.desc).Err(capErr).Msg("gNMI auth rejected, trying next candidate")
				_ = conn.Close()
				lastErr = capErr
				continue
			} else if st != codes.Unimplemented && st != codes.OK {
				log.Debug().Str("target", c.target).Str("strategy", c.desc).Err(capErr).Msg("gNMI probe failed, trying next candidate")
				_ = conn.Close()
				lastErr = capErr
				continue
			}
		}

		d.gnmiConn = conn
		d.gnmiClient = testClient
		log.Info().Str("target", c.target).Str("strategy", c.desc).Msg("Successfully connected to gNMI server")
		return d.gnmiClient, nil
	}

	return nil, fmt.Errorf("failed to connect to gNMI on all candidates: %w", lastErr)
}

func (d *EigrpDaemon) getPolicyDef(policyName string) (*PolicyDef, error) {
	if policyName == "" {
		return nil, nil
	}
	d.mu.RLock()
	if pol, exists := d.policyDefs[policyName]; exists && pol != nil {
		d.mu.RUnlock()
		return pol, nil
	}
	d.mu.RUnlock()

	client, err := d.getGNMIClient()
	if err != nil {
		log.Warn().Err(err).Str("policy", policyName).Msg("Failed to connect to gNMI server for routing-policy")
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &gnmi.GetRequest{
		Path: []*gnmi.Path{
			{
				Elem: []*gnmi.PathElem{
					{Name: "routing-policy"},
					{Name: "policy", Key: map[string]string{"name": policyName}},
				},
			},
		},
		Type:     gnmi.GetRequest_CONFIG,
		Encoding: gnmi.Encoding_JSON_IETF,
	}

	resp, err := client.Get(ctx, req)
	if err != nil {
		log.Warn().Err(err).Str("policy", policyName).Msg("Failed to get routing-policy via gNMI")
		d.resetGNMIClient()
		return nil, err
	}

	for _, notif := range resp.GetNotification() {
		for _, upd := range notif.GetUpdate() {
			val := upd.GetVal()
			if val == nil {
				continue
			}
			jsonBytes := val.GetJsonIetfVal()
			if jsonBytes == nil {
				jsonBytes = val.GetJsonVal()
			}
			if jsonBytes == nil {
				continue
			}

			var wrap struct {
				Policy []PolicyDef `json:"policy"`
			}
			if err := json.Unmarshal(jsonBytes, &wrap); err == nil && len(wrap.Policy) > 0 {
				for _, p := range wrap.Policy {
					if p.Name == policyName {
						d.mu.Lock()
						if d.policyDefs == nil {
							d.policyDefs = make(map[string]*PolicyDef)
						}
						d.policyDefs[policyName] = &p
						d.mu.Unlock()
						return &p, nil
					}
				}
			}

			var pol PolicyDef
			if err := json.Unmarshal(jsonBytes, &pol); err == nil {
				if pol.Name == "" {
					pol.Name = policyName
				}
				d.mu.Lock()
				if d.policyDefs == nil {
					d.policyDefs = make(map[string]*PolicyDef)
				}
				d.policyDefs[policyName] = &pol
				d.mu.Unlock()
				return &pol, nil
			}
		}
	}

	return nil, nil
}

func evaluateRoutePolicy(route CandidateRoute, pol *PolicyDef) (bool, PolicyMetricConfig) {
	return evaluateRoutePolicyWithDefault(route, pol, nil)
}

func evaluateRoutePolicyWithDefault(route CandidateRoute, pol *PolicyDef, defMetric *PolicyMetricConfig) (bool, PolicyMetricConfig) {
	if pol == nil {
		return false, PolicyMetricConfig{}
	}
	isV6 := strings.Contains(route.Prefix, ":")

	for _, stmt := range pol.Statement {
		matched := true
		if stmt.Match.Protocol != "" {
			if !matchProtocol(stmt.Match.Protocol, route.RouteType, route.RouteOwner, isV6) {
				matched = false
			}
		}
		if matched {
			if strings.EqualFold(stmt.Action.PolicyResult, "accept") {
				m := stmt.Action.Eigrp.Metric
				if m.Bandwidth == 0 {
					m.Bandwidth = pol.DefaultAction.Eigrp.Metric.Bandwidth
				}
				if m.Delay == 0 {
					m.Delay = pol.DefaultAction.Eigrp.Metric.Delay
				}
				if m.Reliability == 0 {
					m.Reliability = pol.DefaultAction.Eigrp.Metric.Reliability
				}
				if m.Load == 0 {
					m.Load = pol.DefaultAction.Eigrp.Metric.Load
				}
				if m.Mtu == 0 {
					m.Mtu = pol.DefaultAction.Eigrp.Metric.Mtu
				}
				applySeedMetricFallback(&m, defMetric)
				applyMetricDefaults(&m)
				return true, m
			}
			return false, PolicyMetricConfig{}
		}
	}

	if strings.EqualFold(pol.DefaultAction.PolicyResult, "accept") {
		m := pol.DefaultAction.Eigrp.Metric
		applySeedMetricFallback(&m, defMetric)
		applyMetricDefaults(&m)
		return true, m
	}

	return false, PolicyMetricConfig{}
}

func applySeedMetricFallback(m *PolicyMetricConfig, defMetric *PolicyMetricConfig) {
	if defMetric == nil {
		return
	}
	if m.Bandwidth == 0 && defMetric.Bandwidth > 0 {
		m.Bandwidth = defMetric.Bandwidth
	}
	if m.Delay == 0 && defMetric.Delay > 0 {
		m.Delay = defMetric.Delay
	}
	if m.Reliability == 0 && defMetric.Reliability > 0 {
		m.Reliability = defMetric.Reliability
	}
	if m.Load == 0 && defMetric.Load > 0 {
		m.Load = defMetric.Load
	}
	if m.Mtu == 0 && defMetric.Mtu > 0 {
		m.Mtu = defMetric.Mtu
	}
}

func applyMetricDefaults(m *PolicyMetricConfig) {
	if m.Bandwidth == 0 {
		m.Bandwidth = 100000
	}
	if m.Delay == 0 {
		m.Delay = 100
	}
	if m.Reliability == 0 {
		m.Reliability = 255
	}
	if m.Load == 0 {
		m.Load = 1
	}
	if m.Mtu == 0 {
		m.Mtu = 1500
	}
}

func parseDefaultMetricNotif(jsPath, jsonStr string, existing *PolicyMetricConfig) *PolicyMetricConfig {
	var dm PolicyMetricConfig
	if existing != nil {
		dm = *existing
	}
	if strings.HasSuffix(jsPath, ".bandwidth") {
		var v uint32
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			dm.Bandwidth = v
			return &dm
		}
	} else if strings.HasSuffix(jsPath, ".delay") {
		var v uint32
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			dm.Delay = v
			return &dm
		}
	} else if strings.HasSuffix(jsPath, ".reliability") {
		var v uint8
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			dm.Reliability = v
			return &dm
		}
	} else if strings.HasSuffix(jsPath, ".load") {
		var v uint8
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			dm.Load = v
			return &dm
		}
	} else if strings.HasSuffix(jsPath, ".mtu") {
		var v uint32
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			dm.Mtu = v
			return &dm
		}
	}
	var wrapper struct {
		DefaultMetric    *PolicyMetricConfig `json:"default-metric"`
		DefaultMetricAlt *PolicyMetricConfig `json:"default_metric"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil {
		if wrapper.DefaultMetric != nil {
			return wrapper.DefaultMetric
		}
		if wrapper.DefaultMetricAlt != nil {
			return wrapper.DefaultMetricAlt
		}
	}
	var parsed PolicyMetricConfig
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
		if parsed.Bandwidth > 0 {
			dm.Bandwidth = parsed.Bandwidth
		}
		if parsed.Delay > 0 {
			dm.Delay = parsed.Delay
		}
		if parsed.Reliability > 0 {
			dm.Reliability = parsed.Reliability
		}
		if parsed.Load > 0 {
			dm.Load = parsed.Load
		}
		if parsed.Mtu > 0 {
			dm.Mtu = parsed.Mtu
		}
		return &dm
	}
	return nil
}

func parseMaxPrefixNotif(jsPath, jsonStr string, existing *MaxPrefixConfig) *MaxPrefixConfig {
	var mp MaxPrefixConfig
	if existing != nil {
		mp = *existing
	}
	if strings.HasSuffix(jsPath, ".limit") {
		var v uint32
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			mp.Limit = v
			return &mp
		}
	} else if strings.HasSuffix(jsPath, ".threshold") || strings.HasSuffix(jsPath, ".warning-threshold") || strings.HasSuffix(jsPath, ".warning_threshold") {
		var v uint8
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			mp.Threshold = v
			return &mp
		}
	} else if strings.HasSuffix(jsPath, ".warning-only") || strings.HasSuffix(jsPath, ".warning_only") {
		var v bool
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil {
			mp.WarningOnly = &v
			return &mp
		}
	}
	var wrapper struct {
		MaximumPrefix    *MaxPrefixConfig `json:"maximum-prefix"`
		MaximumPrefixAlt *MaxPrefixConfig `json:"maximum_prefix"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err == nil {
		if wrapper.MaximumPrefix != nil {
			return wrapper.MaximumPrefix
		}
		if wrapper.MaximumPrefixAlt != nil {
			return wrapper.MaximumPrefixAlt
		}
	}
	var parsed MaxPrefixConfig
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
		if parsed.Limit > 0 {
			mp.Limit = parsed.Limit
		}
		if parsed.Threshold > 0 {
			mp.Threshold = parsed.Threshold
		}
		if parsed.WarningOnly != nil {
			v := *parsed.WarningOnly
			mp.WarningOnly = &v
		}
		return &mp
	}
	return nil
}

func (d *EigrpDaemon) TriggerRedistSync(netinst string) {
	if netinst == "" {
		netinst = "default"
	}
	d.InvalidateCandidateRouteCache(netinst)
	if d.redistChan != nil {
		select {
		case d.redistChan <- netinst:
		default:
		}
	}
}

func (d *EigrpDaemon) RedistributionWorker(ctx context.Context) {
	var debounceTimer *time.Timer
	var debounceC <-chan time.Time
	dirty := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		case ni := <-d.redistChan:
			if ni == "" || ni == "*" || ni == "all" {
				d.mu.RLock()
				for name := range d.instances {
					dirty[name] = true
				}
				d.mu.RUnlock()
			} else {
				dirty[ni] = true
			}
			if debounceTimer == nil {
				debounceTimer = time.NewTimer(300 * time.Millisecond)
				debounceC = debounceTimer.C
			} else {
				if !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}
				debounceTimer.Reset(300 * time.Millisecond)
			}
		case <-debounceC:
			debounceTimer = nil
			debounceC = nil
			instancesToSync := make([]string, 0, len(dirty))
			for ni := range dirty {
				instancesToSync = append(instancesToSync, ni)
			}
			dirty = make(map[string]bool)
			for _, ni := range instancesToSync {
				d.SyncRedistribution(ni)
			}
		}
	}
}

func (d *EigrpDaemon) withdrawAllRedistributed(netinst string) {
	inst := d.GetInstance(netinst)
	if inst == nil {
		return
	}
	d.mu.Lock()
	if len(inst.redistributedRoutes) == 0 {
		d.mu.Unlock()
		return
	}
	type redistItem struct {
		prefix string
		proto  string
	}
	var toWithdraw []redistItem
	for pfx, proto := range inst.redistributedRoutes {
		toWithdraw = append(toWithdraw, redistItem{prefix: pfx, proto: proto})
	}
	inst.redistributedRoutes = make(map[string]string)
	inst.redistributedHashes = make(map[string]string)
	d.mu.Unlock()

	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	for _, item := range toWithdraw {
		cPfx := C.CString(item.prefix)
		cProto := C.CString(item.proto)
		C.srlShimRouteRedistributeRemove(cNetinst, cPfx, cProto)
		C.free(unsafe.Pointer(cPfx))
		C.free(unsafe.Pointer(cProto))
		log.Info().Str("netinst", netinst).Str("prefix", item.prefix).Str("proto", item.proto).Msg("Withdrew redistributed route on shutdown/unconfig")
	}
}

func (d *EigrpDaemon) SyncRedistribution(netinst string) {
	if netinst == "all" || netinst == "*" {
		d.mu.RLock()
		var nis []string
		for ni := range d.instances {
			nis = append(nis, ni)
		}
		d.mu.RUnlock()
		for _, ni := range nis {
			d.SyncRedistribution(ni)
		}
		return
	}
	if netinst == "" {
		netinst = "default"
	}
	d.mu.RLock()
	inst, exists := d.instances[netinst]
	if !exists || inst == nil || inst.adminState == "disable" || inst.asn == 0 {
		d.mu.RUnlock()
		d.withdrawAllRedistributed(netinst)
		return
	}

	v4Policy := inst.GetAfiExportPolicy("ipv4-unicast")
	v6Policy := inst.GetAfiExportPolicy("ipv6-unicast")
	v4Enabled := inst.IsAfiEnabled("ipv4-unicast")
	v6Enabled := inst.IsAfiEnabled("ipv6-unicast")
	var v4DefMetric, v6DefMetric *PolicyMetricConfig
	if dm4 := inst.GetAfiDefaultMetric("ipv4-unicast"); dm4 != nil {
		c := *dm4
		v4DefMetric = &c
	}
	if dm6 := inst.GetAfiDefaultMetric("ipv6-unicast"); dm6 != nil {
		c := *dm6
		v6DefMetric = &c
	}
	d.mu.RUnlock()

	if (!v4Enabled || v4Policy == "") && (!v6Enabled || v6Policy == "") {
		d.withdrawAllRedistributed(netinst)
		return
	}

	acceptedRoutes := make(map[string]CandidateRoute)
	acceptedMetrics := make(map[string]PolicyMetricConfig)
	v4SyncSuccess := false
	v6SyncSuccess := false

	if v4Enabled && v4Policy != "" {
		pol, err := d.getPolicyDef(v4Policy)
		if err != nil || pol == nil {
			log.Warn().Err(err).Str("netinst", netinst).Str("policy", v4Policy).Msg("Failed to get IPv4 export policy definition; skipping IPv4 redistribution sync to prevent route flap")
		} else {
			routes, rErr := getCandidateRoutes(netinst, "ipv4-unicast")
			if rErr != nil {
				log.Warn().Err(rErr).Str("netinst", netinst).Msg("Failed to query IPv4 candidate routes; skipping IPv4 redistribution sync to prevent route flap")
			} else {
				v4SyncSuccess = true
				for _, r := range routes {
					if ok, m := evaluateRoutePolicyWithDefault(r, pol, v4DefMetric); ok {
						acceptedRoutes[r.Prefix] = r
						acceptedMetrics[r.Prefix] = m
					}
				}
			}
		}
	} else {
		v4SyncSuccess = true
	}

	if v6Enabled && v6Policy != "" {
		pol, err := d.getPolicyDef(v6Policy)
		if err != nil || pol == nil {
			log.Warn().Err(err).Str("netinst", netinst).Str("policy", v6Policy).Msg("Failed to get IPv6 export policy definition; skipping IPv6 redistribution sync to prevent route flap")
		} else {
			routes, rErr := getCandidateRoutes(netinst, "ipv6-unicast")
			if rErr != nil {
				log.Warn().Err(rErr).Str("netinst", netinst).Msg("Failed to query IPv6 candidate routes; skipping IPv6 redistribution sync to prevent route flap")
			} else {
				v6SyncSuccess = true
				for _, r := range routes {
					if ok, m := evaluateRoutePolicyWithDefault(r, pol, v6DefMetric); ok {
						acceptedRoutes[r.Prefix] = r
						acceptedMetrics[r.Prefix] = m
					}
				}
			}
		}
	} else {
		v6SyncSuccess = true
	}

	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	type redistItem struct {
		prefix string
		proto  string
	}
	var toWithdraw []redistItem

	d.mu.Lock()
	for oldPfx, oldProto := range inst.redistributedRoutes {
		isV6 := strings.Contains(oldPfx, ":")
		if isV6 && !v6SyncSuccess {
			continue
		}
		if !isV6 && !v4SyncSuccess {
			continue
		}
		if _, ok := acceptedRoutes[oldPfx]; !ok {
			toWithdraw = append(toWithdraw, redistItem{prefix: oldPfx, proto: oldProto})
			delete(inst.redistributedRoutes, oldPfx)
			delete(inst.redistributedHashes, oldPfx)
		}
	}
	d.mu.Unlock()

	// Perform route withdrawals outside d.mu
	for _, item := range toWithdraw {
		cPfx := C.CString(item.prefix)
		cProto := C.CString(item.proto)
		C.srlShimRouteRedistributeRemove(cNetinst, cPfx, cProto)
		C.free(unsafe.Pointer(cPfx))
		C.free(unsafe.Pointer(cProto))
		log.Info().Str("netinst", netinst).Str("prefix", item.prefix).Str("proto", item.proto).Msg("Withdrew redistributed route")
	}

	// Add/update accepted routes outside d.mu
	for pfx, r := range acceptedRoutes {
		metric := acceptedMetrics[pfx]
		normProto := normalizeRedistProtocol(r.RouteType, r.RouteOwner, strings.Contains(r.Prefix, ":"))
		sig := fmt.Sprintf("%s|%s|%d|%d|%d|%d|%d", normProto, r.NextHop, metric.Bandwidth, metric.Delay, metric.Reliability, metric.Load, metric.Mtu)

		d.mu.RLock()
		existingSig := inst.redistributedHashes[pfx]
		d.mu.RUnlock()

		if existingSig == sig {
			continue
		}

		cPfx := C.CString(r.Prefix)
		cProto := C.CString(normProto)
		cNh := C.CString(r.NextHop)
		C.srlShimRouteRedistributeAdd(
			cNetinst,
			cPfx,
			cProto,
			cNh,
			C.uint32_t(metric.Bandwidth),
			C.uint32_t(metric.Delay),
			C.uint8_t(metric.Reliability),
			C.uint8_t(metric.Load),
			C.uint32_t(metric.Mtu),
		)
		C.free(unsafe.Pointer(cPfx))
		C.free(unsafe.Pointer(cProto))
		C.free(unsafe.Pointer(cNh))

		d.mu.Lock()
		inst.redistributedRoutes[pfx] = normProto
		if inst.redistributedHashes == nil {
			inst.redistributedHashes = make(map[string]string)
		}
		inst.redistributedHashes[pfx] = sig
		d.mu.Unlock()

		log.Info().Str("netinst", netinst).Str("prefix", pfx).Str("proto", normProto).Interface("metric", metric).Msg("Synchronized redistributed route in EIGRP")
	}
}
