package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edaniels/golog"
	"github.com/miekg/dns"
	"go.uber.org/multierr"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// Number of Multicast responses sent for a query message (default: 1 < x < 9)
	multicastRepetitions = 2
)

// Register a service by given arguments. This call will take the system's hostname
// and lookup IP by that hostname.
func Register(instance, service, domain string, port int, text []string, ifaces []net.Interface) (*Server, error) {
	return register(instance, service, domain, port, text, ifaces, false)
}

// RegisterDynamic registers a service by the given arguments. This call will take the system's hostname
// and look up IPs as requests come in on a particular interface.
func RegisterDynamic(instance, service, domain string, port int, text []string, ifaces []net.Interface) (*Server, error) {
	return register(instance, service, domain, port, text, ifaces, true)
}

func register(instance, service, domain string, port int, text []string, ifaces []net.Interface, dynamic bool) (*Server, error) {
	entry := NewServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text

	if entry.Instance == "" {
		return nil, errors.New("missing service instance name")
	}
	if entry.Service == "" {
		return nil, errors.New("missing service name")
	}
	if entry.Domain == "" {
		entry.Domain = "local."
	}
	if entry.Port == 0 {
		return nil, errors.New("missing port")
	}

	var err error
	if entry.HostName == "" {
		entry.HostName, err = os.Hostname()
		if err != nil {
			return nil, errors.New("could not determine host")
		}
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}

	if !dynamic {
		for _, iface := range ifaces {
			v4, v6 := addrsForInterface(&iface)
			entry.AddrIPv4 = append(entry.AddrIPv4, v4...)
			entry.AddrIPv6 = append(entry.AddrIPv6, v6...)
		}

		if entry.AddrIPv4 == nil && entry.AddrIPv6 == nil {
			return nil, errors.New("could not determine host IP addresses")
		}
	}

	return newServerForService(entry, ifaces)
}

// RegisterProxy registers a service proxy. This call will skip the hostname/IP lookup and
// will use the provided values.
func RegisterProxy(instance, service, domain string, port int, host string, ips []string, text []string, ifaces []net.Interface) (*Server, error) {
	entry := NewServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text
	entry.HostName = host

	if entry.Instance == "" {
		return nil, errors.New("missing service instance name")
	}
	if entry.Service == "" {
		return nil, errors.New("missing service name")
	}
	if entry.HostName == "" {
		return nil, errors.New("missing host name")
	}
	if entry.Domain == "" {
		entry.Domain = "local"
	}
	if entry.Port == 0 {
		return nil, errors.New("missing port")
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			return nil, fmt.Errorf("failed to parse given IP: %v", ip)
		} else if ipv4 := ipAddr.To4(); ipv4 != nil {
			entry.AddrIPv4 = append(entry.AddrIPv4, ipAddr)
		} else if ipv6 := ipAddr.To16(); ipv6 != nil {
			entry.AddrIPv6 = append(entry.AddrIPv6, ipAddr)
		} else {
			return nil, fmt.Errorf("the IP is neither IPv4 nor IPv6: %#v", ipAddr)
		}
	}

	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}

	return newServerForService(entry, ifaces)
}

func newServerForService(entry *ServiceEntry, ifaces []net.Interface) (*Server, error) {
	s, err := newServer(ifaces)
	if err != nil {
		return nil, err
	}

	s.service = entry
	s.startReceivers()
	s.shutdownEnd.Add(1)
	s.startupWait.Add(1)
	managedGo(s.probe, s.shutdownEnd.Done)
	s.startupWait.Wait()

	return s, nil
}

const (
	qClassCacheFlush uint16 = 1 << 15
)

// Server structure encapsulates both IPv4/IPv6 UDP connections
type Server struct {
	service   *ServiceEntry
	ipv4Conns []ifcConn4Pair
	ipv6Conns []ifcConn6Pair

	shutdownCtx       context.Context
	shutdownCtxCancel func()
	shutdownLock      sync.Mutex
	shutdownEnd       sync.WaitGroup
	isShutdown        bool
	ttl               uint32
	startupWait       sync.WaitGroup
}

type ifcConn4Pair struct {
	*ipv4.PacketConn
	ifc *net.Interface
}

func (p4 ifcConn4Pair) NetInterface() *net.Interface {
	return p4.ifc
}

func (p4 ifcConn4Pair) MulticastDstAddr() *net.UDPAddr {
	return ipv4Addr
}

func (p4 ifcConn4Pair) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, _, addr, err = p4.PacketConn.ReadFrom(p)
	return n, addr, err
}

func (p4 ifcConn4Pair) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return p4.PacketConn.WriteTo(p, nil, addr)
}

type ifcConn6Pair struct {
	*ipv6.PacketConn
	ifc *net.Interface
}

func (p6 ifcConn6Pair) NetInterface() *net.Interface {
	return p6.ifc
}

func (p6 ifcConn6Pair) MulticastDstAddr() *net.UDPAddr {
	return ipv6Addr
}

func (p6 ifcConn6Pair) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, _, addr, err = p6.PacketConn.ReadFrom(p)
	return n, addr, err
}

func (p6 ifcConn6Pair) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return p6.PacketConn.WriteTo(p, nil, addr)
}

type netInterfacePacketConnPairing interface {
	NetInterface() *net.Interface
	net.PacketConn
	MulticastDstAddr() *net.UDPAddr
}

// Constructs server structure
func newServer(ifaces []net.Interface) (*Server, error) {
	if len(ifaces) == 0 {
		return nil, errors.New("must provide at least one interface")
	}
	srv := &Server{
		ttl: 3200,
	}
	ipv4Conns := make([]ifcConn4Pair, 0, len(ifaces))
	for idx, iface := range ifaces {
		ifaceCopy := iface
		ipv4conn, err4 := joinUdp4Multicast([]net.Interface{ifaceCopy})
		if err4 == nil {
			ipv4Conns = append(ipv4Conns, ifcConn4Pair{ipv4conn, &ifaceCopy})
			continue
		}
		var errJoin *multicastJoinError
		if !errors.As(err4, &errJoin) {
			golog.Global().Errorw("[zeroconf] failed to join interface to multicast", "idx", idx, "error", err4)
		}
	}
	if len(ipv4Conns) == 0 {
		golog.Global().Errorw("[zeroconf] no suitable IPv4 interface")
	}

	ipv6Conns := make([]ifcConn6Pair, 0, len(ifaces))
	for idx, iface := range ifaces {
		ifaceCopy := iface
		ipv6conn, err6 := joinUdp6Multicast([]net.Interface{ifaceCopy})
		if err6 == nil {
			ipv6Conns = append(ipv6Conns, ifcConn6Pair{ipv6conn, &ifaceCopy})
			continue
		}
		var errJoin *multicastJoinError
		if !errors.As(err6, &errJoin) {
			golog.Global().Errorw("[zeroconf] failed to join interface to multicast", "idx", idx, "error", err6)
		}
	}
	if len(ipv6Conns) == 0 {
		golog.Global().Errorw("[zeroconf] no suitable IPv4 interface")
	}
	if len(ipv4Conns) == 0 && len(ipv6Conns) == 0 {
		// No supported interface left.
		return nil, errors.New("no supported interface")
	}

	shutdownCtx, shutdownCtxCancel := context.WithCancel(context.Background())
	srv.ipv4Conns = ipv4Conns
	srv.ipv6Conns = ipv6Conns
	srv.shutdownCtx = shutdownCtx
	srv.shutdownCtxCancel = shutdownCtxCancel

	return srv, nil
}

// startReceivers starts both IPv4/6 receiver loops and and waits for the shutdown signal from exit channel
func (s *Server) startReceivers() {
	fmt.Println("STARTING RECV")
	for _, conn := range s.ipv4Conns {
		s.startupWait.Add(1)
		s.shutdownEnd.Add(1)
		var nextInstance bool
		connCopy := conn
		managedGo(func() {
			defer func() {
				nextInstance = true
			}()
			s.recv4(connCopy, !nextInstance)
		}, s.shutdownEnd.Done)
	}
	for _, conn := range s.ipv6Conns {
		s.shutdownEnd.Add(1)
		s.startupWait.Add(1)
		var nextInstance bool
		connCopy := conn
		managedGo(func() {
			defer func() {
				nextInstance = true
			}()
			s.recv6(connCopy, !nextInstance)
		}, s.shutdownEnd.Done)
	}
}

// Shutdown closes all udp connections and unregisters the service
func (s *Server) Shutdown() {
	s.shutdown()
}

// SetText updates and announces the TXT records
func (s *Server) SetText(text []string) {
	s.service.Text = text
	s.announceText()
}

// TTL sets the TTL for DNS replies
func (s *Server) TTL(ttl uint32) {
	s.ttl = ttl
}

// Shutdown server will close currently open connections & channel
func (s *Server) shutdown() error {
	s.shutdownLock.Lock()
	defer s.shutdownLock.Unlock()
	if s.isShutdown {
		return errors.New("server is already shutdown")
	}

	err := s.unregister()

	s.shutdownCtxCancel()

	for _, conn := range s.ipv4Conns {
		conn.Close()
	}
	for _, conn := range s.ipv6Conns {
		conn.Close()
	}

	// Wait for connection and routines to be closed
	s.shutdownEnd.Wait()
	s.isShutdown = true

	return err
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv4(ifcConnPair ifcConn4Pair, firstInstance bool) {
	firstRecv := firstInstance
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.shutdownCtx.Done():
			return
		default:
			if firstRecv {
				s.startupWait.Done()
				firstRecv = false
			}
			n, from, err := ifcConnPair.ReadFrom(buf)
			if err != nil {
				continue
			}
			_ = s.parsePacket(buf[:n], ifcConnPair, from)
		}
	}
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv6(ifcConnPair ifcConn6Pair, firstInstance bool) {
	firstRecv := firstInstance
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.shutdownCtx.Done():
			return
		default:
			if firstRecv {
				s.startupWait.Done()
				firstRecv = false
			}
			n, from, err := ifcConnPair.ReadFrom(buf)
			if err != nil {
				continue
			}
			_ = s.parsePacket(buf[:n], ifcConnPair, from)
		}
	}
}

// parsePacket is used to parse an incoming packet
func (s *Server) parsePacket(packet []byte, ifcConnPair netInterfacePacketConnPairing, from net.Addr) error {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		// log.Printf("[ERR] zeroconf: Failed to unpack packet: %v", err)
		return err
	}
	return s.handleQuery(&msg, ifcConnPair, from)
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, ifcConnPair netInterfacePacketConnPairing, from net.Addr) error {
	// Ignore questions with authoritative section for now
	if len(query.Ns) > 0 {
		return nil
	}

	// Handle each question
	var err error
	for _, q := range query.Question {
		resp := dns.Msg{}
		resp.SetReply(query)
		resp.Compress = true
		resp.RecursionDesired = false
		resp.Authoritative = true
		resp.Question = nil // RFC6762 section 6 "responses MUST NOT contain any questions"
		resp.Answer = []dns.RR{}
		resp.Extra = []dns.RR{}
		fmt.Println("GOT A QUESTION")
		if err = s.handleQuestion(q, &resp, query, ifcConnPair.NetInterface()); err != nil {
			// log.Printf("[ERR] zeroconf: failed to handle question %v: %v", q, err)
			continue
		}
		// Check if there is an answer
		if len(resp.Answer) == 0 {
			continue
		}

		if isUnicastQuestion(q) {
			// Send unicast
			if e := s.unicastResponse(&resp, ifcConnPair, from); e != nil {
				err = e
			}
		} else {
			// Send mulicast
			if e := s.multicastResponse(&resp, ifcConnPair); e != nil {
				err = e
			}
		}
	}

	return err
}

// RFC6762 7.1. Known-Answer Suppression
func isKnownAnswer(resp *dns.Msg, query *dns.Msg) bool {
	if len(resp.Answer) == 0 || len(query.Answer) == 0 {
		return false
	}

	if resp.Answer[0].Header().Rrtype != dns.TypePTR {
		return false
	}
	answer := resp.Answer[0].(*dns.PTR)

	for _, known := range query.Answer {
		hdr := known.Header()
		if hdr.Rrtype != answer.Hdr.Rrtype {
			continue
		}
		ptr := known.(*dns.PTR)
		if ptr.Ptr == answer.Ptr && hdr.Ttl >= answer.Hdr.Ttl/2 {
			// log.Printf("skipping known answer: %v", ptr)
			return true
		}
	}

	return false
}

// handleQuestion is used to handle an incoming question
func (s *Server) handleQuestion(q dns.Question, resp *dns.Msg, query *dns.Msg, ifc *net.Interface) error {
	if s.service == nil {
		return nil
	}

	fmt.Println("QUERY FOR NAME")
	switch q.Name {
	case s.service.ServiceTypeName():
		s.serviceTypeName(resp, s.ttl)
		if isKnownAnswer(resp, query) {
			resp.Answer = nil
		}

	case s.service.ServiceName():
		s.composeBrowsingAnswers(resp, ifc)
		if isKnownAnswer(resp, query) {
			resp.Answer = nil
		}

	case s.service.ServiceInstanceName():
		s.composeLookupAnswers(resp, s.ttl, ifc, false)
	default:
		// handle matching subtype query
		for _, subtype := range s.service.Subtypes {
			subtype = fmt.Sprintf("%s._sub.%s", subtype, s.service.ServiceName())
			if q.Name == subtype {
				s.composeBrowsingAnswers(resp, ifc)
				if isKnownAnswer(resp, query) {
					resp.Answer = nil
				}
				break
			}
		}
	}

	return nil
}

func (s *Server) composeBrowsingAnswers(resp *dns.Msg, ifc *net.Interface) {
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Ptr: s.service.ServiceInstanceName(),
	}
	resp.Answer = append(resp.Answer, ptr)

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Txt: s.service.Text,
	}
	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	resp.Extra = append(resp.Extra, srv, txt)

	resp.Extra = s.appendAddrs(resp.Extra, s.ttl, ifc, false)
}

func (s *Server) composeLookupAnswers(resp *dns.Msg, ttl uint32, ifc *net.Interface, flushCache bool) {
	// From RFC6762
	//    The most significant bit of the rrclass for a record in the Answer
	//    Section of a response message is the Multicast DNS cache-flush bit
	//    and is discussed in more detail below in Section 10.2, "Announcements
	//    to Flush Outdated Cache Entries".
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceInstanceName(),
	}
	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | qClassCacheFlush,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | qClassCacheFlush,
			Ttl:    ttl,
		},
		Txt: s.service.Text,
	}
	dnssd := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceTypeName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceName(),
	}
	resp.Answer = append(resp.Answer, srv, txt, ptr, dnssd)

	for _, subtype := range s.service.Subtypes {
		resp.Answer = append(resp.Answer,
			&dns.PTR{
				Hdr: dns.RR_Header{
					Name:   subtype,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Ptr: s.service.ServiceInstanceName(),
			})
	}

	resp.Answer = s.appendAddrs(resp.Answer, ttl, ifc, flushCache)
}

func (s *Server) serviceTypeName(resp *dns.Msg, ttl uint32) {
	// From RFC6762
	// 9.  Service Type Enumeration
	//
	//    For this purpose, a special meta-query is defined.  A DNS query for
	//    PTR records with the name "_services._dns-sd._udp.<Domain>" yields a
	//    set of PTR records, where the rdata of each PTR record is the two-
	//    label <Service> name, plus the same domain, e.g.,
	//    "_http._tcp.<Domain>".
	dnssd := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceTypeName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceName(),
	}
	resp.Answer = append(resp.Answer, dnssd)
}

// Perform probing & announcement
// TODO: implement a proper probing & conflict resolution
func (s *Server) probe() {
	q := new(dns.Msg)
	q.SetQuestion(s.service.ServiceInstanceName(), dns.TypePTR)
	q.RecursionDesired = false

	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Txt: s.service.Text,
	}
	q.Ns = []dns.RR{srv, txt}

	randomizer := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < multicastRepetitions; i++ {
		for idx, ifcConnPair := range s.ipv4Conns {
			if err := s.multicastResponse(q, ifcConnPair); err != nil {
				golog.Global().Errorw("[zeroconf] failed to send probe on ipv4", "idx", idx, "error", err)
			}
		}
		for idx, ifcConnPair := range s.ipv6Conns {
			if err := s.multicastResponse(q, ifcConnPair); err != nil {
				golog.Global().Errorw("[zeroconf] failed to send probe on ipv6", "idx", idx, "error", err)
			}
		}
		if i == 0 {
			s.startupWait.Done()
		}
		if !selectContextOrWait(s.shutdownCtx, time.Duration(randomizer.Intn(250))*time.Millisecond) {
			return
		}
	}

	// From RFC6762
	//    The Multicast DNS responder MUST send at least two unsolicited
	//    responses, one second apart. To provide increased robustness against
	//    packet loss, a responder MAY send up to eight unsolicited responses,
	//    provided that the interval between unsolicited responses increases by
	//    at least a factor of two with every response sent.
	timeout := 1 * time.Second
	for i := 0; i < multicastRepetitions; i++ {
		sendResponse := func(ifcConnPair netInterfacePacketConnPairing) {
			resp := new(dns.Msg)
			resp.MsgHdr.Response = true
			// TODO: make response authoritative if we are the publisher
			resp.Compress = true
			resp.Answer = []dns.RR{}
			resp.Extra = []dns.RR{}
			s.composeLookupAnswers(resp, s.ttl, ifcConnPair.NetInterface(), true)
			if err := s.multicastResponse(resp, ifcConnPair); err != nil {
				golog.Global().Errorw("[zeroconf] failed to send announcement", "error", err.Error())
			}
		}
		for _, ifcConnPair := range s.ipv4Conns {
			sendResponse(ifcConnPair)
		}
		for _, ifcConnPair := range s.ipv6Conns {
			sendResponse(ifcConnPair)
		}
		if !selectContextOrWait(s.shutdownCtx, timeout) {
			return
		}
		timeout *= 2
	}
}

// announceText sends a Text announcement with cache flush enabled
func (s *Server) announceText() {
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | qClassCacheFlush,
			Ttl:    s.ttl,
		},
		Txt: s.service.Text,
	}

	resp.Answer = []dns.RR{txt}
	for _, ifcConnPair := range s.ipv4Conns {
		s.multicastResponse(resp, ifcConnPair)
	}
	for _, ifcConnPair := range s.ipv6Conns {
		s.multicastResponse(resp, ifcConnPair)
	}
}

func (s *Server) unregister() error {
	resp := new(dns.Msg)
	resp.MsgHdr.Response = true
	resp.Answer = []dns.RR{}
	resp.Extra = []dns.RR{}
	s.composeLookupAnswers(resp, 0, nil, true)
	var errs error
	for _, conn := range s.ipv4Conns {
		errs = multierr.Combine(errs, s.multicastResponse(resp, conn))
	}
	for _, conn := range s.ipv6Conns {
		errs = multierr.Combine(errs, s.multicastResponse(resp, conn))
	}
	return errs
}

func (s *Server) appendAddrs(list []dns.RR, ttl uint32, ifc *net.Interface, flushCache bool) []dns.RR {
	v4 := s.service.AddrIPv4
	v6 := s.service.AddrIPv6
	if len(v4) == 0 && len(v6) == 0 && ifc != nil {
		a4, a6 := addrsForInterface(ifc)
		v4 = append(v4, a4...)
		v6 = append(v6, a6...)
	}
	if ttl > 0 {
		// RFC6762 Section 10 says A/AAAA records SHOULD
		// use TTL of 120s, to account for network interface
		// and IP address changes.
		ttl = 120
	}
	var cacheFlushBit uint16
	if flushCache {
		cacheFlushBit = qClassCacheFlush
	}
	for _, ipv4 := range v4 {
		a := &dns.A{
			Hdr: dns.RR_Header{
				Name:   s.service.HostName,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET | cacheFlushBit,
				Ttl:    ttl,
			},
			A: ipv4,
		}
		list = append(list, a)
	}
	for _, ipv6 := range v6 {
		aaaa := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   s.service.HostName,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET | cacheFlushBit,
				Ttl:    ttl,
			},
			AAAA: ipv6,
		}
		list = append(list, aaaa)
	}
	return list
}

func addrsForInterface(iface *net.Interface) ([]net.IP, []net.IP) {
	var v4, v6, v6local []net.IP
	addrs, _ := iface.Addrs()
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				v4 = append(v4, ipnet.IP)
			} else {
				switch ip := ipnet.IP.To16(); ip != nil {
				case ip.IsGlobalUnicast():
					v6 = append(v6, ipnet.IP)
				case ip.IsLinkLocalUnicast():
					v6local = append(v6local, ipnet.IP)
				}
			}
		}
	}
	if len(v6) == 0 {
		v6 = v6local
	}
	return v4, v6
}

// unicastResponse is used to send a unicast response packet
func (s *Server) unicastResponse(resp *dns.Msg, ifcConnPair netInterfacePacketConnPairing, from net.Addr) error {
	buf, err := resp.Pack()
	if err != nil {
		return err
	}
	addr := from.(*net.UDPAddr)
	_, err = ifcConnPair.WriteTo(buf, addr)
	return err
}

// multicastResponse us used to send a multicast response packet
func (s *Server) multicastResponse(msg *dns.Msg, ifcConnPair netInterfacePacketConnPairing) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	ifcConnPair.WriteTo(buf, ifcConnPair.MulticastDstAddr())
	return nil
}

func isUnicastQuestion(q dns.Question) bool {
	// From RFC6762
	// 18.12.  Repurposing of Top Bit of qclass in Question Section
	//
	//    In the Question Section of a Multicast DNS query, the top bit of the
	//    qclass field is used to indicate that unicast responses are preferred
	//    for this particular question.  (See Section 5.4.)
	return q.Qclass&qClassCacheFlush != 0
}
