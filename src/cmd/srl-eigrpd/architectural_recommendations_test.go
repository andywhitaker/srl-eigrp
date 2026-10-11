package main

import (
	"encoding/binary"
	"net"
	"os"
	"syscall"
	"testing"
)

// TestSocketOptions_ConstantsAndDSCPCS6 verifies that native socket options and DSCP CS6
// constants match Linux kernel ABI and Nokia SR Linux native datapath requirements.
func TestSocketOptions_ConstantsAndDSCPCS6(t *testing.T) {
	// DSCP CS6 (Class Selector 6) is binary 110000 (decimal 48).
	// When packed into IPv4 TOS or IPv6 Traffic Class (left-shifted by 2 bits):
	// 48 << 2 = 192 = 0xc0.
	const expectedCS6Tos = 0xc0
	if (48 << 2) != expectedCS6Tos {
		t.Fatalf("CS6 DSCP value must shift to 0xc0, got 0x%02x", 48<<2)
	}

	// Verify standard socket option values on Linux
	if syscall.IP_HDRINCL != 3 {
		t.Errorf("expected IP_HDRINCL to be 3, got %d", syscall.IP_HDRINCL)
	}
	if syscall.IP_TOS != 1 {
		t.Errorf("expected IP_TOS to be 1, got %d", syscall.IP_TOS)
	}
	if syscall.IP_PKTINFO != 8 {
		t.Errorf("expected IP_PKTINFO to be 8, got %d", syscall.IP_PKTINFO)
	}
	if syscall.IP_MULTICAST_TTL != 33 {
		t.Errorf("expected IP_MULTICAST_TTL to be 33, got %d", syscall.IP_MULTICAST_TTL)
	}
	if syscall.IP_MULTICAST_LOOP != 34 {
		t.Errorf("expected IP_MULTICAST_LOOP to be 34, got %d", syscall.IP_MULTICAST_LOOP)
	}
	if syscall.IPV6_RECVPKTINFO != 49 {
		t.Errorf("expected IPV6_RECVPKTINFO to be 49, got %d", syscall.IPV6_RECVPKTINFO)
	}
	if syscall.IPV6_MULTICAST_HOPS != 18 {
		t.Errorf("expected IPV6_MULTICAST_HOPS to be 18, got %d", syscall.IPV6_MULTICAST_HOPS)
	}
	if syscall.IPV6_MULTICAST_LOOP != 19 {
		t.Errorf("expected IPV6_MULTICAST_LOOP to be 19, got %d", syscall.IPV6_MULTICAST_LOOP)
	}
	if syscall.IPV6_TCLASS != 67 {
		t.Errorf("expected IPV6_TCLASS to be 67, got %d", syscall.IPV6_TCLASS)
	}

	// Test real setsockopt calls on a test UDP socket (doesn't require root)
	fd4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err == nil {
		defer syscall.Close(fd4)

		// Test IP_TOS setsockopt with DSCP CS6 (0xc0)
		if err := syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_TOS, expectedCS6Tos); err != nil {
			t.Errorf("failed setsockopt IP_TOS 0xc0: %v", err)
		}
		// Test IP_PKTINFO setsockopt
		if err := syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1); err != nil {
			t.Errorf("failed setsockopt IP_PKTINFO: %v", err)
		}
		// Test IP_MULTICAST_LOOP = 0
		if err := syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0); err != nil {
			t.Errorf("failed setsockopt IP_MULTICAST_LOOP: %v", err)
		}
		// Test IP_MULTICAST_TTL = 1
		if err := syscall.SetsockoptInt(fd4, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1); err != nil {
			t.Errorf("failed setsockopt IP_MULTICAST_TTL: %v", err)
		}
	}

	fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err == nil {
		defer syscall.Close(fd6)

		// Test IPV6_TCLASS setsockopt with DSCP CS6 (0xc0)
		if err := syscall.SetsockoptInt(fd6, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, expectedCS6Tos); err != nil {
			t.Errorf("failed setsockopt IPV6_TCLASS 0xc0: %v", err)
		}
		// Test IPV6_RECVPKTINFO
		if err := syscall.SetsockoptInt(fd6, syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1); err != nil {
			t.Errorf("failed setsockopt IPV6_RECVPKTINFO: %v", err)
		}
		// Test IPV6_MULTICAST_LOOP = 0
		if err := syscall.SetsockoptInt(fd6, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, 0); err != nil {
			t.Errorf("failed setsockopt IPV6_MULTICAST_LOOP: %v", err)
		}
		// Test IPV6_MULTICAST_HOPS = 1
		if err := syscall.SetsockoptInt(fd6, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 1); err != nil {
			t.Errorf("failed setsockopt IPV6_MULTICAST_HOPS: %v", err)
		}
	}
}

// TestSRL_EIGRP_DISABLE_PKT_FD_Toggle verifies that the AF_PACKET packet socket
// can be programmatically and environmentally disabled.
func TestSRL_EIGRP_DISABLE_PKT_FD_Toggle(t *testing.T) {
	// Save existing environment variable
	origEnv, hadEnv := os.LookupEnv("SRL_EIGRP_DISABLE_PKT_FD")
	defer func() {
		if hadEnv {
			os.Setenv("SRL_EIGRP_DISABLE_PKT_FD", origEnv)
		} else {
			os.Unsetenv("SRL_EIGRP_DISABLE_PKT_FD")
		}
		ShimSetPktFdDisabled(false)
	}()

	os.Unsetenv("SRL_EIGRP_DISABLE_PKT_FD")
	ShimSetPktFdDisabled(false)

	if ShimGetPktFdDisabled() {
		t.Fatal("expected ShimGetPktFdDisabled to be false when unset")
	}

	// Test programmatic toggle
	ShimSetPktFdDisabled(true)
	if !ShimGetPktFdDisabled() {
		t.Fatal("expected ShimGetPktFdDisabled to be true after programmatic enable")
	}

	ShimSetPktFdDisabled(false)
	if ShimGetPktFdDisabled() {
		t.Fatal("expected ShimGetPktFdDisabled to be false after programmatic disable")
	}

	// Test environment variable values
	envTests := []struct {
		val      string
		expected bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"YES", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"random", false},
	}

	for _, tt := range envTests {
		os.Setenv("SRL_EIGRP_DISABLE_PKT_FD", tt.val)
		got := ShimGetPktFdDisabled()
		if got != tt.expected {
			t.Errorf("env SRL_EIGRP_DISABLE_PKT_FD=%q: expected %v, got %v", tt.val, tt.expected, got)
		}
	}
}

// TestPacketDeduplicationLogic verifies cross-socket deduplication between b->fd (rx_source 1)
// and b->pkt_fd (rx_source 2) while allowing consecutive packets from the same rx_source.
func TestPacketDeduplicationLogic(t *testing.T) {
	ShimDedupReset()
	defer ShimDedupReset()

	srcIPv4 := net.ParseIP("192.168.1.1").To4()
	dstIPv4 := net.ParseIP("224.0.0.10").To4()
	payload := []byte{0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00} // EIGRP Hello header

	hash := ShimPacketHash(syscall.AF_INET, srcIPv4, dstIPv4, payload)
	if hash == 0 {
		t.Fatal("expected non-zero packet hash")
	}

	const (
		rxSrcFD    = 1 // b->fd (netns raw socket)
		rxSrcPktFD = 2 // b->pkt_fd (root AF_PACKET socket)
	)

	ipID := uint16(0x1234)
	csum := uint16(0x5678)
	pktLen := uint16(len(payload))

	// 1. First packet arrives on b->fd (rx_source 1) -> MUST NOT be duplicate
	isDup := ShimDedupCheck(rxSrcFD, uint8(syscall.AF_INET), hash, pktLen, ipID, csum)
	if isDup {
		t.Fatal("initial packet on b->fd should not be marked as duplicate")
	}

	// 2. Same packet arrives on b->pkt_fd (rx_source 2) within deduplication window -> MUST BE DUPLICATE
	isDup = ShimDedupCheck(rxSrcPktFD, uint8(syscall.AF_INET), hash, pktLen, ipID, csum)
	if !isDup {
		t.Fatal("duplicate packet arriving on b->pkt_fd from b->fd must be marked as duplicate")
	}

	// 3. Periodic hello packet arrives again on b->fd (same rx_source 1) -> MUST NOT be marked duplicate!
	// (Prevents dropping consecutive hellos arriving on the same socket)
	isDup = ShimDedupCheck(rxSrcFD, uint8(syscall.AF_INET), hash, pktLen, ipID, csum)
	if isDup {
		t.Fatal("subsequent packet on same rx_source 1 must not be marked as duplicate of itself")
	}

	// 4. Packet with different checksum or IP ID arrives on b->pkt_fd -> MUST NOT be duplicate
	isDup = ShimDedupCheck(rxSrcPktFD, uint8(syscall.AF_INET), hash, pktLen, ipID+1, csum)
	if isDup {
		t.Fatal("packet with different ip_id must not be marked as duplicate")
	}

	// 5. Reset cache -> original packet should be accepted again
	ShimDedupReset()
	isDup = ShimDedupCheck(rxSrcPktFD, uint8(syscall.AF_INET), hash, pktLen, ipID, csum)
	if isDup {
		t.Fatal("after dedup reset, packet must not be marked as duplicate")
	}
}

// parseEthernetFrame parses Ethernet and 802.1Q/802.1ad VLAN tags exactly as srl_cshim_sys.c does.
func parseEthernetFrame(frame []byte) (ethHdrLen int, vlanID uint16, innerEtherType uint16) {
	if len(frame) < 14 {
		return 0, 0, 0
	}
	ethHdrLen = 14
	ethType := binary.BigEndian.Uint16(frame[12:14])
	for ethType == 0x8100 || ethType == 0x88a8 {
		if len(frame) < ethHdrLen+4 {
			break
		}
		tci := binary.BigEndian.Uint16(frame[ethHdrLen : ethHdrLen+2])
		vlanID = tci & 0x0FFF
		ethHdrLen += 4
		ethType = binary.BigEndian.Uint16(frame[ethHdrLen-2 : ethHdrLen])
	}
	innerEtherType = ethType
	return ethHdrLen, vlanID, innerEtherType
}

// TestVlanTagParsingAndSubinterfaceDisambiguation tests Ethernet frame decoding for:
// - Untagged frames
// - 802.1Q single-tagged (0x8100)
// - 802.1ad single-tagged (0x88a8)
// - Double-tagged QinQ (0x88a8 outer + 0x8100 inner)
// - Double-tagged QinQ (0x8100 outer + 0x8100 inner)
// and verifies that subinterfaces sharing a root parent interface are correctly disambiguated
// via subnet matching and VLAN ID matching.
func TestVlanTagParsingAndSubinterfaceDisambiguation(t *testing.T) {
	macHdr := []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x0a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	// 1. Untagged IPv4 frame
	untagged := append(macHdr, 0x08, 0x00)    // EtherType 0x0800
	payload := []byte{0x45, 0xc0, 0x00, 0x28} // IPv4 header start (DSCP CS6 = 0xc0)
	untagged = append(untagged, payload...)
	hdrLen, vlan, proto := parseEthernetFrame(untagged)
	if hdrLen != 14 || vlan != 0 || proto != 0x0800 {
		t.Fatalf("untagged parse failed: hdrLen=%d vlan=%d proto=0x%04x", hdrLen, vlan, proto)
	}

	// 2. Single-tagged 802.1Q (0x8100) with VLAN ID 10
	singleTagged := append(macHdr, 0x81, 0x00, 0x00, 0x0a, 0x08, 0x00)
	singleTagged = append(singleTagged, payload...)
	hdrLen, vlan, proto = parseEthernetFrame(singleTagged)
	if hdrLen != 18 || vlan != 10 || proto != 0x0800 {
		t.Fatalf("single 802.1Q parse failed: hdrLen=%d vlan=%d proto=0x%04x", hdrLen, vlan, proto)
	}

	// 3. Single-tagged 802.1ad (0x88a8) with VLAN ID 20
	single88a8 := append(macHdr, 0x88, 0xa8, 0x00, 0x14, 0x08, 0x00)
	single88a8 = append(single88a8, payload...)
	hdrLen, vlan, proto = parseEthernetFrame(single88a8)
	if hdrLen != 18 || vlan != 20 || proto != 0x0800 {
		t.Fatalf("single 802.1ad parse failed: hdrLen=%d vlan=%d proto=0x%04x", hdrLen, vlan, proto)
	}

	// 4. Double-tagged QinQ: 0x88a8 (outer VLAN 100) + 0x8100 (inner VLAN 200)
	qinq1 := append(macHdr, 0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x08, 0x00)
	qinq1 = append(qinq1, payload...)
	hdrLen, vlan, proto = parseEthernetFrame(qinq1)
	if hdrLen != 22 || vlan != 200 || proto != 0x0800 {
		t.Fatalf("QinQ 88a8+8100 parse failed: hdrLen=%d vlan=%d proto=0x%04x", hdrLen, vlan, proto)
	}

	// 5. Double-tagged QinQ: 0x8100 (outer VLAN 300) + 0x8100 (inner VLAN 400)
	qinq2 := append(macHdr, 0x81, 0x00, 0x01, 0x2c, 0x81, 0x00, 0x01, 0x90, 0x86, 0xdd) // IPv6
	qinq2 = append(qinq2, payload...)
	hdrLen, vlan, proto = parseEthernetFrame(qinq2)
	if hdrLen != 22 || vlan != 400 || proto != 0x86dd {
		t.Fatalf("QinQ 8100+8100 parse failed: hdrLen=%d vlan=%d proto=0x%04x", hdrLen, vlan, proto)
	}

	// 6. Real C shim subinterface disambiguation and cross-port isolation test:
	ShimTestClearInterfaces()
	defer ShimTestClearInterfaces()

	// Setup topology:
	// Port 1 (root_ifindex=10):
	//   - ethernet-1/1.10: ifindex 101, root_ifindex 10, IP 10.10.10.1/24, IPv4 active
	//   - ethernet-1/1.20: ifindex 102, root_ifindex 10, IP 10.10.20.1/24, IPv4 active
	//   - ethernet-1/1.0:  ifindex 100, root_ifindex 10, IP 10.10.0.1/24, IPv4 active (untagged)
	// Port 2 (root_ifindex=20):
	//   - ethernet-1/2.10: ifindex 201, root_ifindex 20, IP 10.10.20.2/24, IPv4 active
	ShimTestRegisterInterface("default", "ethernet-1/1.0", 100, 10, "10.10.0.1", 24, false, true)
	ShimTestRegisterInterface("default", "ethernet-1/1.10", 101, 10, "10.10.10.1", 24, false, true)
	ShimTestRegisterInterface("default", "ethernet-1/1.20", 102, 10, "10.10.20.1", 24, false, true)
	ShimTestRegisterInterface("default", "ethernet-1/2.10", 201, 20, "10.10.20.2", 24, false, true)

	// Test Case A: Cross-Port Interface Isolation
	// Packet arrives on Port 2 (sll_ifindex=20) with source IP 10.10.20.5 (which is within Port 1's 10.10.20.0/24).
	// Under buggy behavior without strict root_ifindex check, it could leak to Port 1 (ifindex 102).
	// With strict root_ifindex isolation, it MUST resolve to Port 2 (ifindex 201).
	resolved := ShimTestResolveInterfaceV4("default", 20, 0, "10.10.20.5", "224.0.0.10")
	if resolved != 201 {
		t.Fatalf("cross-port isolation failed: packet on port 2 resolved to %d, expected 201", resolved)
	}

	// Test Case B: VLAN ID disambiguation on Port 1
	// Packet arrives on Port 1 (sll_ifindex=10) with VLAN ID 20.
	resolved = ShimTestResolveInterfaceV4("default", 10, 20, "0.0.0.0", "224.0.0.10")
	if resolved != 102 {
		t.Fatalf("VLAN 20 disambiguation failed: expected 102, got %d", resolved)
	}

	// Packet arrives on Port 1 (sll_ifindex=10) with VLAN ID 10.
	resolved = ShimTestResolveInterfaceV4("default", 10, 10, "0.0.0.0", "224.0.0.10")
	if resolved != 101 {
		t.Fatalf("VLAN 10 disambiguation failed: expected 101, got %d", resolved)
	}

	// Test Case C: Subnet matching disambiguation on Port 1
	// Untagged packet on Port 1 with source 10.10.20.5 -> matches 10.10.20.0/24 (ifindex 102)
	resolved = ShimTestResolveInterfaceV4("default", 10, 0, "10.10.20.5", "224.0.0.10")
	if resolved != 102 {
		t.Fatalf("subnet matching failed for 10.10.20.5: expected 102, got %d", resolved)
	}

	// Untagged packet on Port 1 with source 10.10.10.5 -> matches 10.10.10.0/24 (ifindex 101)
	resolved = ShimTestResolveInterfaceV4("default", 10, 0, "10.10.10.5", "224.0.0.10")
	if resolved != 101 {
		t.Fatalf("subnet matching failed for 10.10.10.5: expected 101, got %d", resolved)
	}

	// Test Case D: Destination IP matching on Port 1 (unicast to interface IP)
	resolved = ShimTestResolveInterfaceV4("default", 10, 0, "192.168.99.1", "10.10.20.1")
	if resolved != 102 {
		t.Fatalf("dst IP match failed: expected 102, got %d", resolved)
	}

	// Test Case E: Untagged fallback on Port 1
	resolved = ShimTestResolveInterfaceV4("default", 10, 0, "172.16.1.1", "224.0.0.10")
	if resolved != 100 {
		t.Fatalf("untagged fallback failed: expected 100 (.0), got %d", resolved)
	}

	// Test Case F: Real C shim IPv6 resolution and cross-port isolation
	ShimTestClearInterfaces()
	ShimTestRegisterInterface("default", "ethernet-1/1.0", 100, 10, "fe80::10", 64, true, true)
	ShimTestRegisterInterface("default", "ethernet-1/1.20", 102, 10, "fe80::12", 64, true, true)
	ShimTestRegisterInterface("default", "ethernet-1/2.0", 200, 20, "fe80::20", 64, true, true)

	// VLAN 20 on Port 1 (sll_ifindex=10) resolves to 102
	resolvedV6 := ShimTestResolveInterfaceV6("default", 10, 20, "fe80::99", "ff02::a")
	if resolvedV6 != 102 {
		t.Fatalf("IPv6 VLAN 20 resolution failed: expected 102, got %d", resolvedV6)
	}

	// Multicast on Port 2 (sll_ifindex=20) must resolve to Port 2 interface (200), never Port 1
	resolvedV6 = ShimTestResolveInterfaceV6("default", 20, 0, "fe80::99", "ff02::a")
	if resolvedV6 != 200 {
		t.Fatalf("IPv6 cross-port isolation failed: packet on port 2 resolved to %d, expected 200", resolvedV6)
	}

	// Multicast on Port 1 (sll_ifindex=10) untagged resolves to Port 1 (.0 -> 100)
	resolvedV6 = ShimTestResolveInterfaceV6("default", 10, 0, "fe80::99", "ff02::a")
	if resolvedV6 != 100 {
		t.Fatalf("IPv6 Port 1 resolution failed: expected 100, got %d", resolvedV6)
	}
}

// TestBPFFilterBytecodeExecution rigorously verifies that the cBPF filter generated
// by srl_build_bpf_filter correctly executes in kernel space:
//   - Verifies ifindex filtering (discards packets from non-EIGRP root interfaces)
//   - Verifies untagged, single-tagged 802.1Q (0x8100), 802.1ad (0x88a8),
//     and double-tagged QinQ (0x88a8+0x8100, 0x8100+0x8100) packets
//   - Verifies protocol 88 matches and non-88 drops (TCP/UDP)
func TestBPFFilterBytecodeExecution(t *testing.T) {
	activeIfindexes := []uint32{10, 20}

	buildIPv4Frame := func(vlanMode string, proto byte) []byte {
		mac := []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x0a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
		var frame []byte
		switch vlanMode {
		case "untagged":
			frame = append(mac, 0x08, 0x00) // EtherType IPv4
		case "802.1q":
			frame = append(mac, 0x81, 0x00, 0x00, 0x0a, 0x08, 0x00) // 802.1Q VLAN 10 + IPv4
		case "802.1ad":
			frame = append(mac, 0x88, 0xa8, 0x00, 0x14, 0x08, 0x00) // 802.1ad VLAN 20 + IPv4
		case "qinq-ad-q":
			frame = append(mac, 0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x08, 0x00) // 88a8 + 8100 + IPv4
		case "qinq-q-q":
			frame = append(mac, 0x81, 0x00, 0x01, 0x2c, 0x81, 0x00, 0x01, 0x90, 0x08, 0x00) // 8100 + 8100 + IPv4
		default:
			panic("unknown mode")
		}
		ipHdr := make([]byte, 20)
		ipHdr[0] = 0x45
		ipHdr[9] = proto
		return append(frame, ipHdr...)
	}

	buildIPv6Frame := func(vlanMode string, nextHdr byte) []byte {
		mac := []byte{0x33, 0x33, 0x00, 0x00, 0x0a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
		var frame []byte
		switch vlanMode {
		case "untagged":
			frame = append(mac, 0x86, 0xdd) // EtherType IPv6
		case "802.1q":
			frame = append(mac, 0x81, 0x00, 0x00, 0x0a, 0x86, 0xdd)
		case "802.1ad":
			frame = append(mac, 0x88, 0xa8, 0x00, 0x14, 0x86, 0xdd)
		case "qinq-ad-q":
			frame = append(mac, 0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x86, 0xdd)
		case "qinq-q-q":
			frame = append(mac, 0x81, 0x00, 0x01, 0x2c, 0x81, 0x00, 0x01, 0x90, 0x86, 0xdd)
		default:
			panic("unknown mode")
		}
		ip6Hdr := make([]byte, 40)
		ip6Hdr[0] = 0x60
		ip6Hdr[6] = nextHdr
		return append(frame, ip6Hdr...)
	}

	modes := []string{"untagged", "802.1q", "802.1ad", "qinq-ad-q", "qinq-q-q"}

	// 1. Verify all IPv4 proto 88 variations PASS on matching ifindex
	for _, mode := range modes {
		pkt := buildIPv4Frame(mode, 88)
		ret := ShimTestRunBPFFilter(activeIfindexes, pkt, 10)
		if ret == 0 {
			t.Errorf("expected BPF filter to accept IPv4 %s proto 88 on ifindex 10, but dropped", mode)
		}
		ret = ShimTestRunBPFFilter(activeIfindexes, pkt, 20)
		if ret == 0 {
			t.Errorf("expected BPF filter to accept IPv4 %s proto 88 on ifindex 20, but dropped", mode)
		}
	}

	// 2. Verify all IPv6 next-header 88 variations PASS on matching ifindex
	for _, mode := range modes {
		pkt := buildIPv6Frame(mode, 88)
		ret := ShimTestRunBPFFilter(activeIfindexes, pkt, 10)
		if ret == 0 {
			t.Errorf("expected BPF filter to accept IPv6 %s next-header 88 on ifindex 10, but dropped", mode)
		}
		ret = ShimTestRunBPFFilter(activeIfindexes, pkt, 20)
		if ret == 0 {
			t.Errorf("expected BPF filter to accept IPv6 %s next-header 88 on ifindex 20, but dropped", mode)
		}
	}

	// 3. Verify non-88 protocols DROP (e.g. TCP=6, UDP=17) across all modes
	for _, mode := range modes {
		pktTCP4 := buildIPv4Frame(mode, 6)
		if ret := ShimTestRunBPFFilter(activeIfindexes, pktTCP4, 10); ret != 0 {
			t.Errorf("expected BPF filter to DROP IPv4 %s TCP packet, but accepted (ret=%d)", mode, ret)
		}
		pktUDP4 := buildIPv4Frame(mode, 17)
		if ret := ShimTestRunBPFFilter(activeIfindexes, pktUDP4, 10); ret != 0 {
			t.Errorf("expected BPF filter to DROP IPv4 %s UDP packet, but accepted (ret=%d)", mode, ret)
		}
		pktTCP6 := buildIPv6Frame(mode, 6)
		if ret := ShimTestRunBPFFilter(activeIfindexes, pktTCP6, 10); ret != 0 {
			t.Errorf("expected BPF filter to DROP IPv6 %s TCP packet, but accepted (ret=%d)", mode, ret)
		}
	}

	// 4. Verify packets on non-matching ifindex DROP even if proto is 88
	for _, mode := range modes {
		pkt := buildIPv4Frame(mode, 88)
		if ret := ShimTestRunBPFFilter(activeIfindexes, pkt, 99); ret != 0 {
			t.Errorf("expected BPF filter to DROP packet on non-matching ifindex 99, but accepted (ret=%d)", ret)
		}
	}

	// 5. Verify empty active interfaces DROP all packets
	pkt := buildIPv4Frame("untagged", 88)
	if ret := ShimTestRunBPFFilter(nil, pkt, 10); ret != 0 {
		t.Errorf("expected BPF filter with no active interfaces to DROP, but accepted (ret=%d)", ret)
	}
}
