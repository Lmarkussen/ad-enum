// sccm-pxe is the deliberately small AD-Enum CRED-1 acquisition helper.
//
// The PXE request/reply and bounded TFTP mechanics are derived from the
// authorized CinderPath implementation (internal/cred1/pxe_transport*.go and
// pxe_bootstrap.go).  This helper intentionally stops after obtaining server-
// supplied path metadata and the bounded raw boot.var artifact.  It does not
// import media keys, decrypt boot media, request MP policy, decrypt CMS, or
// recover task-sequence variables.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	clientPort = 68
	proxyPort  = 4011
	serverPort = 69
	maxPayload = 2048
	maxPath    = 256
	maxFiles   = 2
	maxBytes   = 256 << 10
	blockSize  = 512
)

type result struct {
	DP               string     `json:"dp"`
	PXE              string     `json:"pxe"`
	WDS              string     `json:"wds"`
	TFTP             string     `json:"tftp"`
	BootFile         string     `json:"boot_file"`
	VariablesPath    string     `json:"variables_path"`
	BCDPath          string     `json:"bcd_path"`
	MediaProtection  string     `json:"media_protection"`
	Artifacts        []artifact `json:"artifacts"`
	SecretInspection string     `json:"secret_inspection"`
	Errors           []string   `json:"errors"`
}
type artifact struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
	State string `json:"state"`
}

func main() {
	target := flag.String("target", "", "one authorized PXE DP IPv4 address")
	iface := flag.String("interface", "", "capture interface")
	timeout := flag.Duration("timeout", 10*time.Second, "maximum PXE exchange time")
	maxFilesFlag := flag.Int("max-files", maxFiles, "maximum artifact files")
	maxFileBytesFlag := flag.Int("max-file-bytes", maxBytes, "maximum bytes per artifact")
	maxTotalBytesFlag := flag.Int("max-total-bytes", maxBytes, "maximum bytes total")
	flag.Parse()
	out := result{PXE: "UNKNOWN", WDS: "UNKNOWN", TFTP: "UNKNOWN", MediaProtection: "UNKNOWN", SecretInspection: "NOT ATTEMPTED"}
	if *target == "" {
		out.Errors = append(out.Errors, "target is required")
		emit(out)
		return
	}
	if *maxFilesFlag < 1 || *maxFilesFlag > maxFiles || *maxFileBytesFlag < 1 || *maxFileBytesFlag > maxBytes || *maxTotalBytesFlag < 1 || *maxTotalBytesFlag > maxBytes {
		out.Errors = append(out.Errors, "artifact limits exceed safe helper bounds")
		emit(out)
		return
	}
	dp, err := netip.ParseAddr(*target)
	if err != nil || !dp.Is4() {
		out.Errors = append(out.Errors, "target must be an IPv4 address")
		emit(out)
		return
	}
	out.DP = dp.String()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *iface == "" {
		*iface = routeInterface(dp)
	}
	if *iface == "" {
		out.Errors = append(out.Errors, "no capture interface found")
		emit(out)
		return
	}
	reply, err := acquireReply(ctx, *iface, dp)
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
		emit(out)
		return
	}
	out.PXE, out.WDS = "CONFIRMED", "CONFIRMED"
	paths, err := parseOptions(reply.payload)
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
		emit(out)
		return
	}
	out.BootFile, out.VariablesPath, out.BCDPath = paths[2], paths[0], paths[1]
	raw, err := fetchTFTP(ctx, dp, paths[0], *maxFileBytesFlag, *maxTotalBytesFlag)
	if err != nil {
		out.TFTP = "FAILED"
		out.Artifacts = append(out.Artifacts, artifact{Path: paths[0], State: "FAILED"})
		out.Errors = append(out.Errors, err.Error())
		emit(out)
		return
	}
	out.TFTP, out.MediaProtection = "CONFIRMED", "PROTECTED_OR_ENCRYPTED"
	// The raw WDS boot.var envelope is recorded only as bounded metadata. Its
	// contents are intentionally not decrypted or parsed by this helper.
	out.Artifacts = append(out.Artifacts, artifact{Path: paths[0], Bytes: len(raw), State: "RETRIEVED_BOUNDED_RAW"})
	emit(out)
}

func emit(v result) { _ = json.NewEncoder(os.Stdout).Encode(v) }

func routeInterface(dp netip.Addr) string {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dp.AsSlice(), Port: proxyPort})
	if err != nil {
		return ""
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	ifs, _ := net.Interfaces()
	for _, iface := range ifs {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			local, _, _ := net.ParseCIDR(a.String())
			if local != nil && local.Equal(ip) {
				return iface.Name
			}
		}
	}
	return ""
}

type frame struct {
	src, dst     netip.Addr
	sport, dport uint16
	payload      []byte
}

func acquireReply(ctx context.Context, ifaceName string, dp netip.Addr) (frame, error) {
	var out frame
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return out, err
	}
	clientIP, err := interfaceIPv4(iface)
	if err != nil {
		return out, err
	}
	xid, request := pxeRequest(clientIP)
	handle, err := pcap.OpenLive(ifaceName, maxPayload+256, true, 100*time.Millisecond)
	if err != nil {
		return out, fmt.Errorf("PXE capture requires libpcap/capture privileges: %w", err)
	}
	defer handle.Close()
	if err = handle.SetBPFFilter(fmt.Sprintf("udp and src host %s and src port %d and dst port %d", dp, proxyPort, clientPort)); err != nil {
		return out, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: clientIP.AsSlice(), Port: clientPort})
	if err != nil {
		return out, err
	}
	defer conn.Close()
	if _, err = conn.WriteToUDP(request, &net.UDPAddr{IP: dp.AsSlice(), Port: proxyPort}); err != nil {
		return out, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		data, _, e := handle.ReadPacketData()
		if e == pcap.NextErrorTimeoutExpired {
			continue
		}
		if e != nil {
			return out, e
		}
		f, e := parseFrame(data)
		if e == nil && f.src == dp && f.sport == proxyPort && f.dport == clientPort && len(f.payload) >= 240 && f.payload[0] == 2 && binary.BigEndian.Uint32(f.payload[4:8]) == xid {
			return f, nil
		}
	}
	return out, errors.New("PXE reply timeout")
}

func pxeRequest(ip netip.Addr) (uint32, []byte) {
	xid := uint32(time.Now().UnixNano())
	var machineID [16]byte
	_, _ = rand.Read(machineID[:])
	p := make([]byte, 236)
	p[0], p[1], p[2] = 1, 1, 6
	binary.BigEndian.PutUint32(p[4:8], xid)
	copy(p[12:16], ip.AsSlice())
	p = append(p, 99, 130, 83, 99, 53, 1, 3, 55, 11, 3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135, 93, 2, 0, 0, 250, 21, 0x0c, 1, 1, 0x0d, 2, 8, 0, 1, 2, 0, 7, 0x0e, 1, 1, 5, 4, 0, 0, 0, 0x11, 0xff, 60, 9, 'P', 'X', 'E', 'C', 'l', 'i', 'e', 'n', 't', 97, 17, 0)
	p = append(p, machineID[:]...)
	p = append(p, 255)
	return xid, p
}

func interfaceIPv4(i *net.Interface) (netip.Addr, error) {
	addrs, err := i.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip != nil && ip.To4() != nil {
			return netip.AddrFrom4([4]byte(ip.To4())), nil
		}
	}
	return netip.Addr{}, errors.New("interface has no IPv4")
}
func parseFrame(b []byte) (frame, error) {
	if len(b) < 42 || binary.BigEndian.Uint16(b[12:14]) != 0x0800 {
		return frame{}, errors.New("not IPv4")
	}
	o := 14
	ih := int(b[o]&15) * 4
	if len(b) < o+ih+8 || b[o+9] != 17 {
		return frame{}, errors.New("not UDP")
	}
	u := o + ih
	n := int(binary.BigEndian.Uint16(b[u+4 : u+6]))
	if n < 8 || len(b) < u+n {
		return frame{}, errors.New("truncated UDP")
	}
	return frame{netip.AddrFrom4([4]byte(b[o+12 : o+16])), netip.AddrFrom4([4]byte(b[o+16 : o+20])), binary.BigEndian.Uint16(b[u : u+2]), binary.BigEndian.Uint16(b[u+2 : u+4]), b[u+8 : u+n]}, nil
}

func parseOptions(payload []byte) ([3]string, error) {
	var out [3]string
	if len(payload) < 240 {
		return out, errors.New("PXE response lacks DHCP options")
	}
	options := payload[240:]
	var a, b, boot []byte
	for i := 0; i < len(options); {
		code := options[i]
		i++
		if code == 0 {
			continue
		}
		if code == 255 {
			break
		}
		if i >= len(options) {
			return out, errors.New("truncated DHCP option")
		}
		n := int(options[i])
		i++
		if n > len(options)-i {
			return out, errors.New("truncated DHCP option value")
		}
		v := options[i : i+n]
		i += n
		if code == 243 {
			if a != nil {
				return out, errors.New("duplicate option 243")
			}
			a = v
		}
		if code == 252 {
			if b != nil {
				return out, errors.New("duplicate option 252")
			}
			b = v
		}
		if code == 67 {
			boot = v
		}
	}
	if len(a) < 4 || a[0] != 2 {
		return out, errors.New("missing/unsupported option 243")
	}
	n := int(a[1])
	if n < 48 || 2+n+2 > len(a) {
		return out, errors.New("invalid option 243")
	}
	pi := 2 + n + 1
	start := pi + 1
	if start+int(a[pi]) > len(a) {
		return out, errors.New("truncated boot.var path")
	}
	out[0] = validPath(string(a[start:start+int(a[pi])]), ".boot.var")
	out[1] = validPath(string(b), ".boot.bcd")
	if len(boot) > maxPath {
		return out, errors.New("boot filename exceeds bound")
	}
	out[2] = strings.TrimRight(string(boot), "\x00")
	if out[0] == "" || out[1] == "" {
		return out, errors.New("unsafe or missing SMSTemp paths")
	}
	return out, nil
}
func validPath(p, suffix string) string {
	p = strings.TrimRight(p, "\x00")
	rest := strings.TrimPrefix(p, `\SMSTemp\`)
	if len(p) > maxPath || rest == p || rest == "" || strings.ContainsAny(rest, `\\/`) || strings.Contains(rest, "..") || !strings.HasSuffix(strings.ToLower(p), suffix) {
		return ""
	}
	return p
}

func fetchTFTP(ctx context.Context, dp netip.Addr, path string, maxArtifact, maxTotal int) ([]byte, error) {
	conn, e := net.ListenUDP("udp4", nil)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	rrq := append([]byte{0, 1}, []byte(path)...)
	rrq = append(rrq, 0)
	rrq = append(rrq, []byte("octet\x00")...)
	server := &net.UDPAddr{IP: dp.AsSlice(), Port: serverPort}
	if _, e = conn.WriteToUDP(rrq, server); e != nil {
		return nil, e
	}
	var out []byte
	buf := make([]byte, 4+blockSize)
	for block := uint16(1); block < maxFiles*256; block++ {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, peer, e := conn.ReadFromUDP(buf)
		if e != nil {
			return nil, e
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if peer.IP.String() != dp.String() || n < 4 || binary.BigEndian.Uint16(buf[:2]) != 3 || binary.BigEndian.Uint16(buf[2:4]) != block {
			return nil, errors.New("invalid TFTP response")
		}
		if n-4 > maxArtifact || len(out)+n-4 > maxTotal {
			return nil, errors.New("artifact exceeds bound")
		}
		out = append(out, buf[4:n]...)
		_, _ = conn.WriteToUDP([]byte{0, 4, byte(block >> 8), byte(block)}, peer)
		if n-4 < blockSize {
			return out, nil
		}
	}
	return nil, errors.New("TFTP block limit exceeded")
}
