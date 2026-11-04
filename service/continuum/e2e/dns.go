// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum_e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	dockerclient "github.com/moby/moby/client"

	"github.com/hemilabs/heminetwork/v2/service/continuum"
)

// DNSHandler is a mock DNS server that dynamically generates records
// by inspecting a docker network. We can pre-register records or, when
// missing, it will fall back to inspecting the docker network. This
// allows us to pre-register well known nodes, but also retrieve
// responses for dockerized nodes that can't be pre-registered.
type DNSHandler struct {
	Domain        string
	DockerCli     *dockerclient.Client
	DockerNetwork string

	records map[string][]dns.RR
	nodes   map[string]*nodeEntry
}

type nodeEntry struct {
	secret *continuum.Secret
	port   uint16
}

func NewDNSHandler(domain string) *DNSHandler {
	return &DNSHandler{
		Domain:  domain,
		records: make(map[string][]dns.RR),
		nodes:   make(map[string]*nodeEntry),
	}
}

func (h *DNSHandler) dnsName(name string) string {
	return name + "." + h.Domain + "."
}

func (h *DNSHandler) reverseName(ip net.IP) string {
	ip = ip.To4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip[3], ip[2], ip[1], ip[0])
}

func (h *DNSHandler) txtContent(sec *continuum.Secret, port uint16) string {
	s := "v=" + continuum.DNSAppName + "; identity=" + sec.String()
	if port != 0 {
		s += ";   port=" + strconv.Itoa(int(port)) + ";"
	}
	return s
}

// nodeRecords returns the A and TXT forward records for a node.
func (h *DNSHandler) nodeRecords(fqdn string, ip netip.Addr, port uint16, sec *continuum.Secret) []dns.RR {
	return []dns.RR{
		&dns.A{
			Hdr: dns.Header{
				Name:  fqdn,
				Class: dns.ClassINET,
			},
			A: rdata.A{Addr: ip},
		},
		&dns.TXT{
			Hdr: dns.Header{
				Name:  fqdn,
				Class: dns.ClassINET,
			},
			TXT: rdata.TXT{Txt: []string{h.txtContent(sec, port)}},
		},
	}
}

// addNode registers A and TXT forward records for a node with a known IP.
func (h *DNSHandler) addNode(name string, ip net.IP, port uint16, sec *continuum.Secret) {
	addr, ok := netip.AddrFromSlice(ip.To4())
	if !ok {
		panic(fmt.Sprintf("invalid IPv4 address for %s: %v", name, ip))
	}
	fqdn := h.dnsName(name)
	h.records[fqdn] = h.nodeRecords(fqdn, addr, port, sec)
	h.nodes[fqdn] = &nodeEntry{secret: sec, port: port}
}

// addDynamicNode registers a node's secret without a static IP
func (h *DNSHandler) addDynamicNode(name string, port uint16, sec *continuum.Secret) {
	h.nodes[h.dnsName(name)] = &nodeEntry{secret: sec, port: port}
}

// addPTR registers a PTR record mapping ip to name.domain.
func (h *DNSHandler) addPTR(ip net.IP, name string) {
	rev := h.reverseName(ip)
	h.records[rev] = []dns.RR{
		&dns.PTR{
			Hdr: dns.Header{
				Name:  rev,
				Class: dns.ClassINET,
			},
			PTR: rdata.PTR{Ptr: h.dnsName(name)},
		},
	}
}

func (h *DNSHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)
	m.Authoritative = true

	name := r.Question[0].Header().Name
	if rr, ok := h.records[name]; ok {
		m.Answer = rr
	} else if h.DockerCli != nil {
		rr, err := h.dockerResolve(ctx, name)
		if err == nil {
			m.Answer = rr
		} else {
			m.Rcode = dns.RcodeNameError
		}
	} else {
		m.Rcode = dns.RcodeNameError
	}
	if _, err := io.Copy(w, m); err != nil {
		panic(err)
	}
}

func (h *DNSHandler) dockerResolve(ctx context.Context, queryName string) ([]dns.RR, error) {
	netInfo, err := h.DockerCli.NetworkInspect(ctx, h.DockerNetwork, dockerclient.NetworkInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker network inspect: %w", err)
	}

	suffix := "." + h.Domain + "."

	// If querying for IP, returns a PTR record for reverse lookup
	if strings.HasSuffix(queryName, ".in-addr.arpa.") {
		queryIP, ok := arpaToIPv4(queryName)
		if !ok {
			return nil, fmt.Errorf("invalid arpa name: %s", queryName)
		}
		for _, ep := range netInfo.Network.Containers {
			if ep.IPv4Address.Addr() == queryIP {
				return []dns.RR{
					&dns.PTR{
						Hdr: dns.Header{
							Name:  queryName,
							Class: dns.ClassINET,
						},
						PTR: rdata.PTR{Ptr: ep.Name + suffix},
					},
				}, nil
			}
		}
		return nil, fmt.Errorf("no container with IP %v on %s", queryIP, h.DockerNetwork)
	}

	if !strings.HasSuffix(queryName, suffix) {
		return nil, fmt.Errorf("query %s outside domain %s", queryName, h.Domain)
	}
	containerName := strings.TrimSuffix(queryName, suffix)

	// If querying for domain name, returns A and TXT record
	for _, ep := range netInfo.Network.Containers {
		if ep.Name != containerName {
			continue
		}
		ip := ep.IPv4Address.Addr()
		if !ip.Is4() {
			return nil, fmt.Errorf("invalid IP %q for %s", ep.IPv4Address, containerName)
		}
		entry, ok := h.nodes[queryName]
		if !ok {
			return nil, fmt.Errorf("no node registered for %s", queryName)
		}
		return h.nodeRecords(queryName, ip, entry.port, entry.secret), nil
	}
	return nil, fmt.Errorf("no container %q on network %s", containerName, h.DockerNetwork)
}

func arpaToIPv4(arpa string) (netip.Addr, bool) {
	s := strings.TrimSuffix(arpa, ".in-addr.arpa.")
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return netip.Addr{}, false
		}
		b[3-i] = byte(v)
	}
	return netip.AddrFrom4(b), true
}

func NewDNSServer(ctx context.Context, handler dns.Handler) *dns.Server {
	started := make(chan struct{})
	srv := &dns.Server{
		Addr:              "0.0.0.0:0",
		Net:               "tcp",
		Handler:           handler,
		NotifyStartedFunc: func(_ context.Context) { close(started) },
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
	}()
	select {
	case <-ctx.Done():
		panic(fmt.Errorf("DNS server startup: %w", ctx.Err()))
	case <-started:
	}
	return srv
}
