package main

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
	"github.com/rs/zerolog/log"
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

type InterfaceConfig struct {
	InterfaceName  string                 `json:"interface-name"`
	AdminState     string                 `json:"admin-state,omitempty"`
	Passive        *bool                  `json:"passive,omitempty"`
	HelloInterval  *uint16                `json:"hello-interval,omitempty"`
	HoldTime       *uint16                `json:"hold-time,omitempty"`
	SplitHorizon   *bool                  `json:"split-horizon,omitempty"`
	NextHopSelf    *bool                  `json:"next-hop-self,omitempty"`
	Bandwidth      *uint32                `json:"bandwidth,omitempty"`
	Delay          *uint32                `json:"delay,omitempty"`
	SummaryAddress []SummaryAddressConfig `json:"summary-address,omitempty"`
	Authentication *AuthConfig            `json:"authentication,omitempty"`
	Bfd            *BfdConfig             `json:"bfd,omitempty"`
}

type DefaultInterfaceConfig struct {
	AdminState     string      `json:"admin-state"`
	Passive        bool        `json:"passive"`
	HelloInterval  uint16      `json:"hello-interval"`
	HoldTime       uint16      `json:"hold-time"`
	SplitHorizon   *bool       `json:"split-horizon,omitempty"`
	NextHopSelf    *bool       `json:"next-hop-self,omitempty"`
	Bandwidth      *uint32     `json:"bandwidth,omitempty"`
	Delay          *uint32     `json:"delay,omitempty"`
	Authentication *AuthConfig `json:"authentication,omitempty"`
	Bfd            *BfdConfig  `json:"bfd,omitempty"`
}

type TimersConfig struct {
	ActiveTime uint16 `json:"active-time"`
}

type MetricsConfig struct {
	Bandwidth   uint8  `json:"bandwidth"`
	Load        uint8  `json:"load"`
	Delay       uint8  `json:"delay"`
	Reliability uint8  `json:"reliability"`
	Mtu         uint8  `json:"mtu"`
	K1          *uint8 `json:"k1,omitempty"`
	K2          *uint8 `json:"k2,omitempty"`
	K3          *uint8 `json:"k3,omitempty"`
	K4          *uint8 `json:"k4,omitempty"`
	K5          *uint8 `json:"k5,omitempty"`
	K6          *uint8 `json:"k6,omitempty"`
	RibScale    *uint8 `json:"rib-scale,omitempty"`
}

type PolicyMetricConfig struct {
	Bandwidth   uint32 `json:"bandwidth"`
	Delay       uint32 `json:"delay"`
	Reliability uint8  `json:"reliability"`
	Load        uint8  `json:"load"`
	Mtu         uint32 `json:"mtu"`
}

type AddressFamilyConfig struct {
	Name         string            `json:"name"`
	AdminState   string            `json:"admin-state,omitempty"`
	ExportPolicy string            `json:"export-policy,omitempty"`
	ImportPolicy string            `json:"import-policy,omitempty"`
	Interface    []InterfaceConfig `json:"interface,omitempty"`
}

type IPv6UnicastConfig struct {
	AdminState   string            `json:"admin-state,omitempty"`
	ExportPolicy string            `json:"export-policy,omitempty"`
	ImportPolicy string            `json:"import-policy,omitempty"`
	Interface    []InterfaceConfig `json:"interface,omitempty"`
}

type EigrpConfig struct {
	AdminState       string                  `json:"admin-state"`
	AutonomousSystem uint16                  `json:"autonomous-system"`
	RouterId         string                  `json:"router-id"`
	ExportPolicy     string                  `json:"export-policy"`
	ImportPolicy     string                  `json:"import-policy"`
	Variance         uint8                   `json:"variance"`
	MaximumPaths     uint8                   `json:"maximum-paths"`
	MaximumHops      uint8                   `json:"maximum-hops"`
	RibScale         *uint8                  `json:"rib-scale,omitempty"`
	WideMetrics      *bool                   `json:"wide-metrics,omitempty"`
	GracefulRestart  *GracefulRestartConfig  `json:"graceful-restart,omitempty"`
	Authentication   *AuthConfig             `json:"authentication,omitempty"`
	Timers           *TimersConfig           `json:"timers,omitempty"`
	Metrics          *MetricsConfig          `json:"metrics,omitempty"`
	MetricWeights    *MetricsConfig          `json:"metric-weights,omitempty"`
	DefaultInterface *DefaultInterfaceConfig `json:"default-interface,omitempty"`
	Interface        []InterfaceConfig       `json:"interface,omitempty"`
	IPv6Unicast      *IPv6UnicastConfig      `json:"ipv6-unicast,omitempty"`
	AddressFamily    []AddressFamilyConfig   `json:"address-family,omitempty"`
	Network          []string                `json:"network,omitempty"`
	StaticNeighbor   []StaticNeighborConfig  `json:"static-neighbor,omitempty"`
}

var (
	netinstRegex = regexp.MustCompile(`\.network[-_]instance\{(?:\.name==)?["']?([^}"']+)["']?\}`)
	intfRegex    = regexp.MustCompile(`\.interface\{(?:\.interface-name==|\.name==)?["']?([^}"']+)["']?\}`)
	policyRegex  = regexp.MustCompile(`\.policy\{(?:\.name==)?["']?([^}"']+)["']?\}`)
)

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
		if len(keys) >= 3 && keys[2] != "" {
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
	cNetinst := C.CString(inst.netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	cIfname := C.CString(ifcfg.InterfaceName)
	defer C.free(unsafe.Pointer(cIfname))

	adminUp := true
	if ifcfg.AdminState == "disable" {
		adminUp = false
	} else if ifcfg.AdminState == "" && inst.defaultIntf != nil && inst.defaultIntf.AdminState == "disable" {
		adminUp = false
	}

	passive := false
	if ifcfg.Passive != nil {
		passive = *ifcfg.Passive
	} else if inst.defaultIntf != nil {
		passive = inst.defaultIntf.Passive
	}

	hello := uint16(5)
	if ifcfg.HelloInterval != nil && *ifcfg.HelloInterval > 0 {
		hello = *ifcfg.HelloInterval
	} else if inst.defaultIntf != nil && inst.defaultIntf.HelloInterval > 0 {
		hello = inst.defaultIntf.HelloInterval
	}

	hold := uint16(15)
	if ifcfg.HoldTime != nil && *ifcfg.HoldTime > 0 {
		hold = *ifcfg.HoldTime
	} else if inst.defaultIntf != nil && inst.defaultIntf.HoldTime > 0 {
		hold = inst.defaultIntf.HoldTime
	}

	splitHorizon := true
	if ifcfg.SplitHorizon != nil {
		splitHorizon = *ifcfg.SplitHorizon
	} else if inst.defaultIntf != nil && inst.defaultIntf.SplitHorizon != nil {
		splitHorizon = *inst.defaultIntf.SplitHorizon
	}

	nextHopSelf := false
	if ifcfg.NextHopSelf != nil {
		nextHopSelf = *ifcfg.NextHopSelf
	} else if inst.defaultIntf != nil && inst.defaultIntf.NextHopSelf != nil {
		nextHopSelf = *inst.defaultIntf.NextHopSelf
	}

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

	C.srlShimInterfaceEnable(cNetinst, cIfname, C.bool(passive), C.uint16_t(hello), C.uint16_t(hold), C.bool(adminUp), C.bool(splitHorizon), C.bool(nextHopSelf), C.uint32_t(bandwidth), C.uint32_t(delay))

	authMode := ""
	keychain := ""
	authKey := ""
	if ifcfg.Authentication != nil {
		authMode = ifcfg.Authentication.Mode
		keychain = ifcfg.Authentication.Keychain
		authKey = ifcfg.Authentication.AuthenticationKey
	} else if inst.defaultIntf != nil && inst.defaultIntf.Authentication != nil {
		authMode = inst.defaultIntf.Authentication.Mode
		keychain = inst.defaultIntf.Authentication.Keychain
		authKey = inst.defaultIntf.Authentication.AuthenticationKey
	}

	if authMode != "" {
		cMode := C.CString(authMode)
		cKc := C.CString(keychain)
		cKey := C.CString(authKey)
		C.srlShimInterfaceAuthSet(cNetinst, cIfname, cMode, cKc, cKey)
		C.free(unsafe.Pointer(cMode))
		C.free(unsafe.Pointer(cKc))
		C.free(unsafe.Pointer(cKey))
	} else {
		C.srlShimInterfaceAuthClear(cNetinst, cIfname)
	}

	bfdAdmin := "disable"
	var bfdTx, bfdRx uint32 = 1000000, 1000000
	var bfdMult uint8 = 3
	if ifcfg.Bfd != nil {
		if ifcfg.Bfd.AdminState != "" {
			bfdAdmin = ifcfg.Bfd.AdminState
		}
		if ifcfg.Bfd.DesiredMinimumTxInterval != nil && *ifcfg.Bfd.DesiredMinimumTxInterval > 0 {
			bfdTx = *ifcfg.Bfd.DesiredMinimumTxInterval
		}
		if ifcfg.Bfd.RequiredMinimumReceive != nil && *ifcfg.Bfd.RequiredMinimumReceive > 0 {
			bfdRx = *ifcfg.Bfd.RequiredMinimumReceive
		}
		if ifcfg.Bfd.DetectionMultiplier != nil && *ifcfg.Bfd.DetectionMultiplier > 0 {
			bfdMult = *ifcfg.Bfd.DetectionMultiplier
		}
	} else if inst.defaultIntf != nil && inst.defaultIntf.Bfd != nil {
		if inst.defaultIntf.Bfd.AdminState != "" {
			bfdAdmin = inst.defaultIntf.Bfd.AdminState
		}
		if inst.defaultIntf.Bfd.DesiredMinimumTxInterval != nil && *inst.defaultIntf.Bfd.DesiredMinimumTxInterval > 0 {
			bfdTx = *inst.defaultIntf.Bfd.DesiredMinimumTxInterval
		}
		if inst.defaultIntf.Bfd.RequiredMinimumReceive != nil && *inst.defaultIntf.Bfd.RequiredMinimumReceive > 0 {
			bfdRx = *inst.defaultIntf.Bfd.RequiredMinimumReceive
		}
		if inst.defaultIntf.Bfd.DetectionMultiplier != nil && *inst.defaultIntf.Bfd.DetectionMultiplier > 0 {
			bfdMult = *inst.defaultIntf.Bfd.DetectionMultiplier
		}
	}
	for nbrIP, nbr := range inst.neighbors {
		if normalizeIfName(nbr.Interface) == normalizeIfName(ifcfg.InterfaceName) {
			_ = d.BfdSessionAddOrUpdate(inst.netinst, nbrIP, ifcfg.InterfaceName, bfdAdmin, bfdTx, bfdRx, bfdMult)
		}
	}
}

func (d *EigrpDaemon) applyInterfaceV6(inst *EigrpInstance, ifcfg *InterfaceConfig) {
	cNetinst := C.CString(inst.netinst)
	defer C.free(unsafe.Pointer(cNetinst))

	cIfname := C.CString(ifcfg.InterfaceName)
	defer C.free(unsafe.Pointer(cIfname))

	adminUp := true
	if !inst.hasV6 || ifcfg.AdminState == "disable" {
		adminUp = false
	} else if ifcfg.AdminState == "" && inst.defaultIntf != nil && inst.defaultIntf.AdminState == "disable" {
		adminUp = false
	}

	passive := false
	if ifcfg.Passive != nil {
		passive = *ifcfg.Passive
	} else if inst.defaultIntf != nil {
		passive = inst.defaultIntf.Passive
	}

	hello := uint16(5)
	if ifcfg.HelloInterval != nil && *ifcfg.HelloInterval > 0 {
		hello = *ifcfg.HelloInterval
	} else if inst.defaultIntf != nil && inst.defaultIntf.HelloInterval > 0 {
		hello = inst.defaultIntf.HelloInterval
	}

	hold := uint16(15)
	if ifcfg.HoldTime != nil && *ifcfg.HoldTime > 0 {
		hold = *ifcfg.HoldTime
	} else if inst.defaultIntf != nil && inst.defaultIntf.HoldTime > 0 {
		hold = inst.defaultIntf.HoldTime
	}

	splitHorizon := true
	if ifcfg.SplitHorizon != nil {
		splitHorizon = *ifcfg.SplitHorizon
	} else if inst.defaultIntf != nil && inst.defaultIntf.SplitHorizon != nil {
		splitHorizon = *inst.defaultIntf.SplitHorizon
	}

	nextHopSelf := false
	if ifcfg.NextHopSelf != nil {
		nextHopSelf = *ifcfg.NextHopSelf
	} else if inst.defaultIntf != nil && inst.defaultIntf.NextHopSelf != nil {
		nextHopSelf = *inst.defaultIntf.NextHopSelf
	}

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

	C.srlShimInterfaceEnableV6(cNetinst, cIfname, C.bool(passive), C.uint16_t(hello), C.uint16_t(hold), C.bool(adminUp), C.bool(splitHorizon), C.bool(nextHopSelf), C.uint32_t(bandwidth), C.uint32_t(delay))

	authMode := ""
	keychain := ""
	authKey := ""
	if ifcfg.Authentication != nil {
		authMode = ifcfg.Authentication.Mode
		keychain = ifcfg.Authentication.Keychain
		authKey = ifcfg.Authentication.AuthenticationKey
	} else if inst.defaultIntf != nil && inst.defaultIntf.Authentication != nil {
		authMode = inst.defaultIntf.Authentication.Mode
		keychain = inst.defaultIntf.Authentication.Keychain
		authKey = inst.defaultIntf.Authentication.AuthenticationKey
	}

	if authMode != "" {
		cMode := C.CString(authMode)
		cKc := C.CString(keychain)
		cKey := C.CString(authKey)
		C.srlShimInterfaceAuthSet(cNetinst, cIfname, cMode, cKc, cKey)
		C.free(unsafe.Pointer(cMode))
		C.free(unsafe.Pointer(cKc))
		C.free(unsafe.Pointer(cKey))
	} else {
		C.srlShimInterfaceAuthClear(cNetinst, cIfname)
	}

	bfdAdmin := "disable"
	var bfdTx, bfdRx uint32 = 1000000, 1000000
	var bfdMult uint8 = 3
	if ifcfg.Bfd != nil {
		if ifcfg.Bfd.AdminState != "" {
			bfdAdmin = ifcfg.Bfd.AdminState
		}
		if ifcfg.Bfd.DesiredMinimumTxInterval != nil && *ifcfg.Bfd.DesiredMinimumTxInterval > 0 {
			bfdTx = *ifcfg.Bfd.DesiredMinimumTxInterval
		}
		if ifcfg.Bfd.RequiredMinimumReceive != nil && *ifcfg.Bfd.RequiredMinimumReceive > 0 {
			bfdRx = *ifcfg.Bfd.RequiredMinimumReceive
		}
		if ifcfg.Bfd.DetectionMultiplier != nil && *ifcfg.Bfd.DetectionMultiplier > 0 {
			bfdMult = *ifcfg.Bfd.DetectionMultiplier
		}
	} else if inst.defaultIntf != nil && inst.defaultIntf.Bfd != nil {
		if inst.defaultIntf.Bfd.AdminState != "" {
			bfdAdmin = inst.defaultIntf.Bfd.AdminState
		}
		if inst.defaultIntf.Bfd.DesiredMinimumTxInterval != nil && *inst.defaultIntf.Bfd.DesiredMinimumTxInterval > 0 {
			bfdTx = *inst.defaultIntf.Bfd.DesiredMinimumTxInterval
		}
		if inst.defaultIntf.Bfd.RequiredMinimumReceive != nil && *inst.defaultIntf.Bfd.RequiredMinimumReceive > 0 {
			bfdRx = *inst.defaultIntf.Bfd.RequiredMinimumReceive
		}
		if inst.defaultIntf.Bfd.DetectionMultiplier != nil && *inst.defaultIntf.Bfd.DetectionMultiplier > 0 {
			bfdMult = *inst.defaultIntf.Bfd.DetectionMultiplier
		}
	}
	for nbrIP, nbr := range inst.neighbors {
		if normalizeIfName(nbr.Interface) == normalizeIfName(ifcfg.InterfaceName) {
			_ = d.BfdSessionAddOrUpdate(inst.netinst, nbrIP, ifcfg.InterfaceName, bfdAdmin, bfdTx, bfdRx, bfdMult)
		}
	}
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

		if m.K6 != nil {
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
		if policyName == "" {
			return
		}
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			delete(d.policies, policyName)
			d.mu.Unlock()
			log.Info().Str("policy", policyName).Msg("Removed routing-policy EIGRP metrics")

			d.mu.RLock()
			var affectedInstances []string
			for ni, inst := range d.instances {
				if inst.exportPolicy == policyName {
					affectedInstances = append(affectedInstances, ni)
				}
			}
			d.mu.RUnlock()
			for _, ni := range affectedInstances {
				d.applyRedistribute(ni, "")
			}
			return
		}

		var polWrapper struct {
			Metric PolicyMetricConfig `json:"metric"`
		}
		if err := json.Unmarshal([]byte(jsonStr), &polWrapper); err == nil {
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
				if inst.exportPolicy == policyName {
					affectedInstances = append(affectedInstances, ni)
				}
			}
			d.mu.RUnlock()
			for _, ni := range affectedInstances {
				d.applyRedistribute(ni, policyName)
			}
		}
		return
	}

	if !strings.Contains(jsPath, ".protocols.eigrp") {
		return
	}

	netinst := extractNetinst(cfg)

	// Check if this is a DELETE of the entire EIGRP protocol on this network-instance
	if strings.HasSuffix(jsPath, ".protocols.eigrp") && op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
		log.Info().Str("netinst", netinst).Msg("Deleting EIGRP protocol instance")
		cNetinst := C.CString(netinst)
		C.srlShimInstanceDelete(cNetinst)
		C.free(unsafe.Pointer(cNetinst))
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
			if inst.hasV6 {
				C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
			}
			log.Info().Str("netinst", netinst).Msg("EIGRP instance disabled via admin-state sub-path")
		} else if inst.asn > 0 {
			cRouterId := C.CString(inst.routerId)
			C.srlShimInstanceCreate(cNetinst, C.uint16_t(inst.asn), cRouterId)
			if inst.hasV6 {
				C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
			}
			C.free(unsafe.Pointer(cRouterId))
			d.mu.RLock()
			allIntfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
			for _, ic := range inst.configuredInterfaces {
				allIntfs = append(allIntfs, ic)
			}
			allIntfsV6 := make([]*InterfaceConfig, 0, len(inst.configuredInterfacesV6))
			for _, ic := range inst.configuredInterfacesV6 {
				allIntfsV6 = append(allIntfsV6, ic)
			}
			d.mu.RUnlock()
			for _, ic := range allIntfs {
				d.applyInterface(inst, ic)
			}
			for _, ic := range allIntfsV6 {
				d.applyInterfaceV6(inst, ic)
			}
			log.Info().Str("netinst", netinst).Msg("EIGRP instance enabled via admin-state sub-path")
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
			d.mu.Lock()
			if snIP != "" {
				delete(inst.staticNeighbors, snIP)
			} else {
				inst.staticNeighbors = make(map[string]*StaticNeighborConfig)
			}
			d.mu.Unlock()
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
				log.Info().Str("netinst", netinst).Interface("static_neighbor", sn).Msg("Updated static-neighbor via sub-path")
				go d.CollectAndPublish(context.Background())
			}
		}
		return
	}

	// 2. Handle sub-path default-interface notification
	if strings.Contains(jsPath, ".protocols.eigrp.default-interface") {
		inst := d.GetOrCreateInstance(netinst)

		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			if strings.Contains(jsPath, ".authentication") {
				d.mu.Lock()
				if inst.defaultIntf != nil {
					inst.defaultIntf.Authentication = nil
				}
				intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
				for _, ic := range inst.configuredInterfaces {
					intfs = append(intfs, ic)
				}
				d.mu.Unlock()
				for _, ic := range intfs {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Msg("Deleted default-interface authentication and refreshed interfaces")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".bfd") {
				d.mu.Lock()
				if inst.defaultIntf != nil {
					inst.defaultIntf.Bfd = nil
				}
				intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
				for _, ic := range inst.configuredInterfaces {
					intfs = append(intfs, ic)
				}
				d.mu.Unlock()
				for _, ic := range intfs {
					d.applyInterface(inst, ic)
				}
				log.Info().Str("netinst", netinst).Msg("Deleted default-interface bfd and refreshed interfaces")
				go d.CollectAndPublish(context.Background())
				return
			}
			d.mu.Lock()
			inst.defaultIntf = nil
			intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
			for _, ic := range inst.configuredInterfaces {
				intfs = append(intfs, ic)
			}
			d.mu.Unlock()
			for _, ic := range intfs {
				d.applyInterface(inst, ic)
			}
			log.Info().Str("netinst", netinst).Msg("Deleted default-interface config and refreshed interfaces")
			return
		}

		var defCfg DefaultInterfaceConfig
		if err := json.Unmarshal([]byte(jsonStr), &defCfg); err == nil {
			d.mu.Lock()
			if inst.defaultIntf != nil {
				if defCfg.AdminState == "" {
					defCfg.AdminState = inst.defaultIntf.AdminState
				}
				if defCfg.HelloInterval == 0 {
					defCfg.HelloInterval = inst.defaultIntf.HelloInterval
				}
				if defCfg.HoldTime == 0 {
					defCfg.HoldTime = inst.defaultIntf.HoldTime
				}
				if defCfg.SplitHorizon == nil {
					defCfg.SplitHorizon = inst.defaultIntf.SplitHorizon
				}
				if defCfg.NextHopSelf == nil {
					defCfg.NextHopSelf = inst.defaultIntf.NextHopSelf
				}
				if defCfg.Bandwidth == nil {
					defCfg.Bandwidth = inst.defaultIntf.Bandwidth
				}
				if defCfg.Delay == nil {
					defCfg.Delay = inst.defaultIntf.Delay
				}
				if defCfg.Authentication == nil && !strings.Contains(jsonStr, "\"authentication\"") && (strings.Contains(jsPath, ".passive") || strings.Contains(jsPath, ".admin-state") || strings.Contains(jsPath, ".hello-interval") || strings.Contains(jsPath, ".hold-time") || strings.Contains(jsPath, ".split-horizon") || strings.Contains(jsPath, ".next-hop-self") || strings.Contains(jsPath, ".bandwidth") || strings.Contains(jsPath, ".delay") || strings.Contains(jsPath, ".bfd")) {
					defCfg.Authentication = inst.defaultIntf.Authentication
				}
				if defCfg.Bfd == nil {
					defCfg.Bfd = inst.defaultIntf.Bfd
				}
			}
			inst.defaultIntf = &defCfg
			intfs := make([]*InterfaceConfig, 0, len(inst.configuredInterfaces))
			for _, ic := range inst.configuredInterfaces {
				intfs = append(intfs, ic)
			}
			d.mu.Unlock()
			for _, ic := range intfs {
				d.applyInterface(inst, ic)
			}
			log.Info().Str("netinst", netinst).Interface("default_interface", defCfg).Msg("Updated default-interface config and refreshed interfaces")
		}
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
		var v uint8
		if err := json.Unmarshal([]byte(jsonStr), &v); err == nil && v > 0 {
			cNetinst := C.CString(netinst)
			C.srlShimVarianceUpdate(cNetinst, C.uint8_t(v))
			C.free(unsafe.Pointer(cNetinst))
			inst := d.GetOrCreateInstance(netinst)
			d.mu.Lock()
			inst.variance = v
			d.mu.Unlock()
			log.Info().Str("netinst", netinst).Uint8("variance", v).Msg("Updated EIGRP variance via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 5. Handle sub-path maximum-paths notification
	if strings.Contains(jsPath, ".protocols.eigrp.maximum-paths") {
		var mp uint8
		if err := json.Unmarshal([]byte(jsonStr), &mp); err == nil && mp > 0 {
			cNetinst := C.CString(netinst)
			C.srlShimMaxPathsUpdate(cNetinst, C.uint8_t(mp))
			C.free(unsafe.Pointer(cNetinst))
			inst := d.GetOrCreateInstance(netinst)
			d.mu.Lock()
			inst.maximumPaths = mp
			d.mu.Unlock()
			log.Info().Str("netinst", netinst).Uint8("maximum_paths", mp).Msg("Updated EIGRP maximum-paths via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 6. Handle sub-path maximum-hops notification
	if strings.Contains(jsPath, ".protocols.eigrp.maximum-hops") {
		var mh uint8
		if err := json.Unmarshal([]byte(jsonStr), &mh); err == nil && mh > 0 {
			cNetinst := C.CString(netinst)
			C.srlShimMaxHopsUpdate(cNetinst, C.uint8_t(mh))
			C.free(unsafe.Pointer(cNetinst))
			inst := d.GetOrCreateInstance(netinst)
			d.mu.Lock()
			inst.maximumHops = mh
			d.mu.Unlock()
			log.Info().Str("netinst", netinst).Uint8("maximum_hops", mh).Msg("Updated EIGRP maximum-hops via sub-path notification")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 6a. Handle sub-path graceful-restart notification
	if strings.Contains(jsPath, ".protocols.eigrp.graceful-restart") || strings.Contains(jsPath, ".protocols.eigrp.graceful_restart") {
		inst := d.GetOrCreateInstance(netinst)
		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			inst.gracefulRestart = nil
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

	// 8a. Handle sub-path IPv6 interface notification
	if (strings.Contains(jsPath, ".protocols.eigrp.ipv6-unicast") || strings.Contains(jsPath, ".protocols.eigrp.address-family")) && strings.Contains(jsPath, ".interface") && !strings.Contains(jsPath, ".default-interface") {
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
				if ic, exists := inst.configuredInterfacesV6[ifName]; exists {
					var updatedSA []SummaryAddressConfig
					for _, sa := range ic.SummaryAddress {
						if sa.Prefix != pfx && pfx != "" {
							updatedSA = append(updatedSA, sa)
						}
					}
					ic.SummaryAddress = updatedSA
				}
				d.mu.Unlock()
				log.Info().Str("netinst", netinst).Str("interface", ifName).Str("prefix", pfx).Msg("Deleted IPv6 summary-address on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".authentication") {
				d.mu.Lock()
				if ic, exists := inst.configuredInterfacesV6[ifName]; exists {
					ic.Authentication = nil
				}
				d.mu.Unlock()
				C.srlShimInterfaceAuthClear(cNetinst, cIfname)
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Cleared IPv6 EIGRP authentication on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".bfd") {
				d.mu.Lock()
				if ic, exists := inst.configuredInterfacesV6[ifName]; exists {
					ic.Bfd = nil
				}
				d.mu.Unlock()
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Cleared IPv6 EIGRP bfd on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			d.mu.Lock()
			delete(inst.configuredInterfacesV6, ifName)
			d.mu.Unlock()
			C.srlShimInterfaceDisableV6(cNetinst, cIfname)
			log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Disabled IPv6 EIGRP on deleted interface")
			go d.CollectAndPublish(context.Background())
			return
		}

		if strings.Contains(jsPath, ".summary-address") {
			pfx := extractSummaryPrefix(cfg)
			d.mu.Lock()
			ic := inst.configuredInterfacesV6[ifName]
			if ic == nil {
				ic = &InterfaceConfig{InterfaceName: ifName}
				inst.configuredInterfacesV6[ifName] = ic
			}
			var saCfg SummaryAddressConfig
			_ = json.Unmarshal([]byte(jsonStr), &saCfg)
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
			log.Info().Str("netinst", netinst).Str("interface", ifName).Interface("summary_address", saCfg).Msg("Configured IPv6 summary-address on interface")
			go d.CollectAndPublish(context.Background())
			return
		}

		var intfCfg InterfaceConfig
		if err := json.Unmarshal([]byte(jsonStr), &intfCfg); err == nil {
			intfCfg.InterfaceName = ifName
			d.mu.Lock()
			if existing, exists := inst.configuredInterfacesV6[ifName]; exists && existing != nil {
				if len(intfCfg.SummaryAddress) == 0 && !strings.Contains(jsonStr, "\"summary-address\"") {
					intfCfg.SummaryAddress = existing.SummaryAddress
				}
			}
			inst.configuredInterfacesV6[ifName] = &intfCfg
			hasV6 := inst.hasV6
			d.mu.Unlock()
			if !hasV6 {
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Saved IPv6 interface config while IPv6 is disabled")
				go d.CollectAndPublish(context.Background())
				return
			}
			if inst.asn > 0 {
				cRouterId := C.CString(inst.routerId)
				C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
				C.free(unsafe.Pointer(cRouterId))
			}
			d.applyInterfaceV6(inst, &intfCfg)
			log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Configured IPv6 EIGRP on interface")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 8b. Handle sub-path IPv4 interface notification
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
				if ic, exists := inst.configuredInterfaces[ifName]; exists {
					var updatedSA []SummaryAddressConfig
					for _, sa := range ic.SummaryAddress {
						if sa.Prefix != pfx && pfx != "" {
							updatedSA = append(updatedSA, sa)
						}
					}
					ic.SummaryAddress = updatedSA
				}
				d.mu.Unlock()
				log.Info().Str("netinst", netinst).Str("interface", ifName).Str("prefix", pfx).Msg("Deleted IPv4 summary-address on interface")
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
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Cleared IPv4 EIGRP authentication on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			if strings.Contains(jsPath, ".bfd") {
				d.mu.Lock()
				if ic, exists := inst.configuredInterfaces[ifName]; exists {
					ic.Bfd = nil
				}
				d.mu.Unlock()
				log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Cleared IPv4 EIGRP bfd on interface")
				go d.CollectAndPublish(context.Background())
				return
			}
			d.mu.Lock()
			delete(inst.configuredInterfaces, ifName)
			d.mu.Unlock()
			C.srlShimInterfaceDisable(cNetinst, cIfname)
			log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Disabled IPv4 EIGRP on deleted interface")
			go d.CollectAndPublish(context.Background())
			return
		}

		if strings.Contains(jsPath, ".summary-address") {
			pfx := extractSummaryPrefix(cfg)
			d.mu.Lock()
			ic := inst.configuredInterfaces[ifName]
			if ic == nil {
				ic = &InterfaceConfig{InterfaceName: ifName}
				inst.configuredInterfaces[ifName] = ic
			}
			var saCfg SummaryAddressConfig
			_ = json.Unmarshal([]byte(jsonStr), &saCfg)
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
			log.Info().Str("netinst", netinst).Str("interface", ifName).Interface("summary_address", saCfg).Msg("Configured IPv4 summary-address on interface")
			go d.CollectAndPublish(context.Background())
			return
		}

		var intfCfg InterfaceConfig
		if err := json.Unmarshal([]byte(jsonStr), &intfCfg); err == nil {
			intfCfg.InterfaceName = ifName
			d.mu.Lock()
			if existing, exists := inst.configuredInterfaces[ifName]; exists && existing != nil {
				if len(intfCfg.SummaryAddress) == 0 && !strings.Contains(jsonStr, "\"summary-address\"") {
					intfCfg.SummaryAddress = existing.SummaryAddress
				}
			}
			inst.configuredInterfaces[ifName] = &intfCfg
			d.mu.Unlock()
			d.applyInterface(inst, &intfCfg)
			log.Info().Str("netinst", netinst).Str("interface", ifName).Msg("Configured IPv4 EIGRP on interface")
			go d.CollectAndPublish(context.Background())
		}
		return
	}

	// 8c. Handle sub-path ipv6-unicast container notification
	if strings.Contains(jsPath, ".protocols.eigrp.ipv6-unicast") && !strings.Contains(jsPath, ".interface") {
		inst := d.GetOrCreateInstance(netinst)
		cNetinst := C.CString(netinst)
		defer C.free(unsafe.Pointer(cNetinst))

		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			d.mu.Lock()
			inst.hasV6 = false
			inst.ipv6Unicast = nil
			inst.configuredInterfacesV6 = make(map[string]*InterfaceConfig)
			d.mu.Unlock()
			C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
			log.Info().Str("netinst", netinst).Msg("Deleted IPv6 EIGRP instance")
			go d.CollectAndPublish(context.Background())
			return
		}

		var v6Cfg IPv6UnicastConfig
		if err := json.Unmarshal([]byte(jsonStr), &v6Cfg); err == nil {
			if v6Cfg.AdminState == "disable" {
				d.mu.Lock()
				inst.hasV6 = false
				inst.ipv6Unicast = &v6Cfg
				for _, ifcfg := range v6Cfg.Interface {
					if ifcfg.InterfaceName != "" {
						cfgCopy := ifcfg
						inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
					}
				}
				d.mu.Unlock()
				C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
				log.Info().Str("netinst", netinst).Msg("Disabled IPv6 EIGRP instance via sub-path")
				go d.CollectAndPublish(context.Background())
				return
			}
			d.mu.Lock()
			inst.hasV6 = true
			inst.ipv6Unicast = &v6Cfg
			d.mu.Unlock()
			if inst.asn > 0 {
				cRouterId := C.CString(inst.routerId)
				C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
				C.free(unsafe.Pointer(cRouterId))
			}
			for _, ifcfg := range v6Cfg.Interface {
				if ifcfg.InterfaceName == "" {
					continue
				}
				cfgCopy := ifcfg
				d.mu.Lock()
				inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
				d.mu.Unlock()
				d.applyInterfaceV6(inst, &cfgCopy)
			}
			d.mu.RLock()
			allIntfsV6 := make([]*InterfaceConfig, 0, len(inst.configuredInterfacesV6))
			for _, ic := range inst.configuredInterfacesV6 {
				allIntfsV6 = append(allIntfsV6, ic)
			}
			d.mu.RUnlock()
			for _, ic := range allIntfsV6 {
				d.applyInterfaceV6(inst, ic)
			}
		}
		go d.CollectAndPublish(context.Background())
		return
	}

	// 8d. Handle sub-path address-family notification
	if strings.Contains(jsPath, ".protocols.eigrp.address-family") && !strings.Contains(jsPath, ".interface") {
		inst := d.GetOrCreateInstance(netinst)
		cNetinst := C.CString(netinst)
		defer C.free(unsafe.Pointer(cNetinst))

		if op == ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE {
			C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
			d.mu.Lock()
			inst.configuredInterfacesV6 = make(map[string]*InterfaceConfig)
			d.mu.Unlock()
			log.Info().Str("netinst", netinst).Msg("Deleted IPv6 EIGRP address-family instance")
			go d.CollectAndPublish(context.Background())
			return
		}

		var afCfg AddressFamilyConfig
		if err := json.Unmarshal([]byte(jsonStr), &afCfg); err == nil {
			if strings.HasPrefix(strings.ToLower(afCfg.Name), "ipv6") {
				if afCfg.AdminState == "disable" {
					C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
					d.mu.Lock()
					inst.hasV6 = false
					for _, ifcfg := range afCfg.Interface {
						if ifcfg.InterfaceName != "" {
							cfgCopy := ifcfg
							inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
						}
					}
					d.mu.Unlock()
					log.Info().Str("netinst", netinst).Msg("Disabled IPv6 EIGRP address-family instance via sub-path")
					go d.CollectAndPublish(context.Background())
					return
				}
				if inst.asn > 0 {
					cRouterId := C.CString(inst.routerId)
					C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(inst.asn), cRouterId)
					C.free(unsafe.Pointer(cRouterId))
					for _, ifcfg := range afCfg.Interface {
						if ifcfg.InterfaceName == "" {
							continue
						}
						cfgCopy := ifcfg
						d.mu.Lock()
						inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
						d.mu.Unlock()
						d.applyInterfaceV6(inst, &cfgCopy)
					}
					d.mu.RLock()
					allIntfsV6 := make([]*InterfaceConfig, 0, len(inst.configuredInterfacesV6))
					for _, ic := range inst.configuredInterfacesV6 {
						allIntfsV6 = append(allIntfsV6, ic)
					}
					d.mu.RUnlock()
					for _, ic := range allIntfsV6 {
						d.applyInterfaceV6(inst, ic)
					}
				}
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

	expPolicy := conf.ExportPolicy
	impPolicy := conf.ImportPolicy

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
	inst.exportPolicy = expPolicy
	inst.importPolicy = impPolicy
	if conf.Variance > 0 {
		inst.variance = conf.Variance
	} else if inst.variance == 0 {
		inst.variance = 1
	}
	if conf.MaximumPaths > 0 {
		inst.maximumPaths = conf.MaximumPaths
	} else if inst.maximumPaths == 0 {
		inst.maximumPaths = 4
	}
	if conf.MaximumHops > 0 {
		inst.maximumHops = conf.MaximumHops
	} else if inst.maximumHops == 0 {
		inst.maximumHops = 100
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
	if conf.IPv6Unicast != nil {
		inst.ipv6Unicast = conf.IPv6Unicast
	}
	if len(conf.AddressFamily) > 0 {
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
	if conf.GracefulRestart != nil {
		inst.gracefulRestart = conf.GracefulRestart
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
			if conf.DefaultInterface.Delay == nil {
				conf.DefaultInterface.Delay = inst.defaultIntf.Delay
			}
			if conf.DefaultInterface.Authentication == nil && !strings.Contains(jsonStr, "\"authentication\"") {
				conf.DefaultInterface.Authentication = inst.defaultIntf.Authentication
			}
			if conf.DefaultInterface.Bfd == nil && !strings.Contains(jsonStr, "\"bfd\"") {
				conf.DefaultInterface.Bfd = inst.defaultIntf.Bfd
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
		if conf.IPv6Unicast != nil {
			for _, ifcfg := range conf.IPv6Unicast.Interface {
				if ifcfg.InterfaceName != "" {
					cfgCopy := ifcfg
					inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
				}
			}
		}
		for _, af := range conf.AddressFamily {
			if strings.HasPrefix(strings.ToLower(af.Name), "ipv6") {
				for _, ifcfg := range af.Interface {
					if ifcfg.InterfaceName != "" {
						cfgCopy := ifcfg
						inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
					}
				}
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
		if inst.hasV6 {
			C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(inst.asn))
		}
		log.Info().Str("netinst", netinst).Msg("EIGRP instance disabled")
		go d.CollectAndPublish(context.Background())
		return
	}

	if conf.AutonomousSystem > 0 {
		cRouterId := C.CString(conf.RouterId)
		res := C.srlShimInstanceCreate(cNetinst, C.uint16_t(conf.AutonomousSystem), cRouterId)
		C.free(unsafe.Pointer(cRouterId))

		if res != 0 {
			log.Error().Str("netinst", netinst).Uint16("asn", conf.AutonomousSystem).Msg("Failed to create EIGRP instance")
			return
		}

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

		hasV6 := false
		if conf.IPv6Unicast != nil && conf.IPv6Unicast.AdminState != "disable" {
			hasV6 = true
		}
		for _, af := range conf.AddressFamily {
			if strings.HasPrefix(strings.ToLower(af.Name), "ipv6") && af.AdminState != "disable" {
				hasV6 = true
			}
		}

		inst.hasV6 = hasV6
		if hasV6 {
			cRouterId := C.CString(conf.RouterId)
			v6Res := C.srlShimInstanceCreateV6(cNetinst, C.uint16_t(conf.AutonomousSystem), cRouterId)
			C.free(unsafe.Pointer(cRouterId))
			if v6Res != 0 {
				log.Error().Str("netinst", netinst).Uint16("asn", conf.AutonomousSystem).Msg("Failed to create IPv6 EIGRP instance")
			} else {
				log.Info().Str("netinst", netinst).Uint16("asn", conf.AutonomousSystem).Msg("Created IPv6 EIGRP instance")
			}

			if conf.IPv6Unicast != nil {
				for _, ifcfg := range conf.IPv6Unicast.Interface {
					if ifcfg.InterfaceName == "" {
						continue
					}
					cfgCopy := ifcfg
					d.mu.Lock()
					inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
					d.mu.Unlock()
					d.applyInterfaceV6(inst, &cfgCopy)
				}
			}
			for _, af := range conf.AddressFamily {
				if strings.HasPrefix(strings.ToLower(af.Name), "ipv6") {
					for _, ifcfg := range af.Interface {
						if ifcfg.InterfaceName == "" {
							continue
						}
						cfgCopy := ifcfg
						d.mu.Lock()
						inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
						d.mu.Unlock()
						d.applyInterfaceV6(inst, &cfgCopy)
					}
				}
			}
			d.mu.RLock()
			allIntfsV6 := make([]*InterfaceConfig, 0, len(inst.configuredInterfacesV6))
			for _, ic := range inst.configuredInterfacesV6 {
				allIntfsV6 = append(allIntfsV6, ic)
			}
			d.mu.RUnlock()
			for _, ic := range allIntfsV6 {
				d.applyInterfaceV6(inst, ic)
			}
		} else {
			d.mu.Lock()
			inst.hasV6 = false
			if conf.IPv6Unicast != nil {
				for _, ifcfg := range conf.IPv6Unicast.Interface {
					if ifcfg.InterfaceName == "" {
						continue
					}
					cfgCopy := ifcfg
					inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
				}
			}
			for _, af := range conf.AddressFamily {
				if strings.HasPrefix(strings.ToLower(af.Name), "ipv6") {
					for _, ifcfg := range af.Interface {
						if ifcfg.InterfaceName == "" {
							continue
						}
						cfgCopy := ifcfg
						inst.configuredInterfacesV6[ifcfg.InterfaceName] = &cfgCopy
					}
				}
			}
			d.mu.Unlock()
			C.srlShimInstanceDeleteV6(cNetinst, C.uint16_t(conf.AutonomousSystem))
			log.Info().Str("netinst", netinst).Msg("Disabled or unconfigured IPv6 EIGRP instance")
		}

		if len(conf.StaticNeighbor) > 0 {
			d.mu.Lock()
			for _, sn := range conf.StaticNeighbor {
				if sn.IPAddress != "" {
					cfgCopy := sn
					inst.staticNeighbors[sn.IPAddress] = &cfgCopy
				}
			}
			d.mu.Unlock()
		}

		// Apply interfaces from top-level config
		for _, ifcfg := range conf.Interface {
			if ifcfg.InterfaceName == "" {
				continue
			}
			cfgCopy := ifcfg
			d.mu.Lock()
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
		d.applyRedistribute(netinst, expPolicy)

		if conf.Variance > 0 {
			C.srlShimVarianceUpdate(cNetinst, C.uint8_t(conf.Variance))
		}
		if conf.MaximumPaths > 0 {
			C.srlShimMaxPathsUpdate(cNetinst, C.uint8_t(conf.MaximumPaths))
		}
		if conf.MaximumHops > 0 {
			C.srlShimMaxHopsUpdate(cNetinst, C.uint8_t(conf.MaximumHops))
		}
		if conf.Timers != nil {
			d.applyTimers(netinst, conf.Timers)
		}

		go d.CollectAndPublish(context.Background())
	}
}
