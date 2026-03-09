// Package tunnel provides a Go-based DNS tunnel engine for Android ad blocking.
//
// This package is designed to be compiled with gomobile bind and used from
// Android Kotlin code. It handles TUN packet processing, DNS query forwarding
// (Plain/DoH/DoT/DoQ), domain blocking, SafeSearch enforcement, and
// YouTube restricted mode.
//
// The exported API uses only gomobile-compatible types (string, []byte, int, bool).
package tunnel

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// LogCallback is the interface for receiving DNS query events in Kotlin.
// gomobile will generate the corresponding Java/Kotlin interface.
type LogCallback interface {
	// OnDNSQuery is called for each DNS query processed.
	OnDNSQuery(domain string, blocked bool, queryType int, responseTimeMs int64, appName string, resolvedIP string, blockedBy string)
}

// DomainChecker is the interface for checking if a domain should be blocked.
// The implementation lives in Kotlin (using efficient mmap'd Trie data structures)
// so we don't need to export 200k+ domains to Go.
type DomainChecker interface {
	// IsBlocked returns true if the domain should be blocked.
	IsBlocked(domain string) bool
	// GetBlockReason returns the reason a domain is blocked (e.g., "ad", "security", "custom").
	// Returns empty string if not blocked.
	GetBlockReason(domain string) string
}

// FirewallChecker checks if a DNS query from a specific app should be blocked.
// The implementation lives in Kotlin and uses UID resolution + FirewallManager.
type FirewallChecker interface {
	// ShouldBlock checks if the app owning the DNS connection should be blocked.
	// sourcePort: the source UDP port of the DNS query
	// sourceIP: the source IP address bytes
	// destIP: the destination IP address bytes
	ShouldBlock(appName string) bool
}

// AppResolver interface to allow Kotlin to return the AppName for a connection
type AppResolver interface {
	ResolveApp(sourcePort int, sourceIP []byte, destIP []byte, destPort int) string
}

// SocketProtector is the interface for protecting sockets from VPN routing loop.
// Implemented in Kotlin via VpnService.protect().
type SocketProtector interface {
	// Protect protects a socket file descriptor from the VPN routing loop.
	Protect(fd int) bool
}

// Engine is the main DNS tunnel engine.
// All exported methods use gomobile-compatible types.
type Engine struct {
	protocol        string
	primaryDNS      string
	fallbackDNS     string
	dohURL          string
	responseType    ResponseType
	logCallback     LogCallback
	resolver        *Resolver
	safeSearch      *SafeSearch
	domainChecker   DomainChecker
	firewallChecker FirewallChecker
	appResolver     AppResolver

	adTrie  *MmapTrie
	secTrie *MmapTrie

	mu      sync.Mutex
	running bool
	tunFile *os.File

	// Stats
	totalQueries   atomic.Int64
	blockedQueries atomic.Int64
}

// Stats holds engine statistics.
type Stats struct {
	TotalQueries   int64 `json:"total"`
	BlockedQueries int64 `json:"blocked"`
}

// NewEngine creates a new Engine instance.
func NewEngine() *Engine {
	return &Engine{
		safeSearch:   NewSafeSearch(),
		responseType: ResponseCustomIP,
	}
}

// SetDomainChecker sets the Kotlin-side domain checker.
// This is called before Start() to provide the blocking logic for rules not in the trie (like Custom Rules).
func (e *Engine) SetDomainChecker(checker DomainChecker) {
	e.domainChecker = checker
}

// SetTries loads the native memory-mapped domain tries for blazing-fast lookups in Go.
// It accepts the absolute paths to the ad and security binary trie files.
func (e *Engine) SetTries(adTriePath string, secTriePath string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Close old ones if they exist
	if e.adTrie != nil {
		e.adTrie.Close()
		e.adTrie = nil
	}
	if e.secTrie != nil {
		e.secTrie.Close()
		e.secTrie = nil
	}

	if adTriePath != "" {
		t, err := LoadMmapTrie(adTriePath)
		if err != nil {
			logf("Failed to load Ad Trie: %v", err)
		} else {
			e.adTrie = t
			logf("Loaded Ad Trie recursively from Go native Mmap")
		}
	}

	if secTriePath != "" {
		t, err := LoadMmapTrie(secTriePath)
		if err != nil {
			logf("Failed to load Security Trie: %v", err)
		} else {
			e.secTrie = t
			logf("Loaded Security Trie recursively from Go native Mmap")
		}
	}
}

// SetFirewallChecker sets the Kotlin-side firewall checker.
// This is called before Start() to enable per-app DNS blocking.
func (e *Engine) SetFirewallChecker(checker FirewallChecker) {
	e.firewallChecker = checker
}

// SetAppResolver sets the Kotlin-side app name resolver for logging who made the request.
func (e *Engine) SetAppResolver(resolver AppResolver) {
	e.appResolver = resolver
}

// SetLogCallback sets the callback for DNS query events.
func (e *Engine) SetLogCallback(cb LogCallback) {
	e.logCallback = cb
}

// SetDNS configures the DNS settings.
// protocol: "PLAIN", "DOH", "DOT", "DOQ"
// primary: primary DNS server (e.g., "8.8.8.8")
// fallback: fallback DNS server (e.g., "1.1.1.1"), can be empty
// dohURL: DoH/DoQ server URL (e.g., "https://dns.cloudflare.com/dns-query")
func (e *Engine) SetDNS(protocol, primary, fallback, dohURL string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.protocol = protocol
	e.primaryDNS = primary
	e.fallbackDNS = fallback
	e.dohURL = dohURL
	if e.resolver != nil {
		e.resolver.Configure(ParseProtocol(protocol), primary, fallback, dohURL)
	}
}

// SetBlockResponseType sets how blocked domains are responded to.
// responseType: "CUSTOM_IP" (0.0.0.0), "NXDOMAIN", "REFUSED"
func (e *Engine) SetBlockResponseType(responseType string) {
	e.responseType = ParseResponseType(responseType)
}

// SetSafeSearch enables or disables SafeSearch enforcement.
func (e *Engine) SetSafeSearch(enabled bool) {
	e.safeSearch.SetEnabled(enabled)
}

// SetYouTubeRestricted enables or disables YouTube restricted mode.
func (e *Engine) SetYouTubeRestricted(enabled bool) {
	e.safeSearch.SetYouTubeRestricted(enabled)
}

// Start begins processing DNS packets from the TUN file descriptor.
// protector is called to protect sockets from VPN routing loop.
// This function blocks until Stop() is called.
func (e *Engine) Start(fd int, protector SocketProtector) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.totalQueries.Store(0)
	e.blockedQueries.Store(0)

	// Create resolver with socket protection
	var protectFn func(fd int) bool
	if protector != nil {
		protectFn = func(fd int) bool {
			return protector.Protect(fd)
		}
	}
	e.resolver = NewResolver(protectFn)
	e.resolver.Configure(ParseProtocol(e.protocol), e.primaryDNS, e.fallbackDNS, e.dohURL)
	e.mu.Unlock()

	// Duplicate fd to take proper ownership and avoid Android fdsan unique_fd crashes
	dupFd, err := syscall.Dup(fd)
	if err != nil {
		logf("Failed to dup TUN fd %d: %v", fd, err)
		e.running = false
		return
	}

	// Open TUN file descriptor using the dup'd fd
	e.tunFile = os.NewFile(uintptr(dupFd), "tun")
	if e.tunFile == nil {
		logf("Failed to open TUN fd %d", fd)
		e.running = false
		return
	}

	logf("Engine started, reading from TUN fd=%d", fd)

	// Packet processing loop
	buf := make([]byte, 32767) // MAX_PACKET_SIZE
	for e.running {
		n, err := e.tunFile.Read(buf)
		if err != nil {
			if e.running {
				logf("TUN read error: %v", err)
			}
			break
		}
		if n <= 0 {
			continue
		}

		// Parse the IP packet
		queryInfo := ParseTUNPacket(buf, n)
		if queryInfo == nil {
			continue // Not a DNS query, drop silently
		}

		// Handle DNS query in a goroutine for concurrency
		go e.handleDNSQuery(queryInfo)
	}

	logf("Engine stopped")
}

// Stop stops the engine.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.running = false
	if e.tunFile != nil {
		e.tunFile.Close() // Safely close the duplicated fd
		e.tunFile = nil
	}
	if e.resolver != nil {
		e.resolver.Shutdown()
		// DO NOT set e.resolver = nil to prevent panics in concurrent handleDNSQuery routines
	}
	e.safeSearch.ClearCache()

	if e.adTrie != nil {
		e.adTrie.Close()
		e.adTrie = nil
	}
	if e.secTrie != nil {
		e.secTrie.Close()
		e.secTrie = nil
	}
}

// IsRunning returns whether the engine is currently running.
func (e *Engine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// GetStats returns engine statistics as JSON.
func (e *Engine) GetStats() string {
	stats := Stats{
		TotalQueries:   e.totalQueries.Load(),
		BlockedQueries: e.blockedQueries.Load(),
	}
	data, _ := json.Marshal(stats)
	return string(data)
}

// handleDNSQuery processes a single DNS query.
func (e *Engine) handleDNSQuery(queryInfo *DNSQueryInfo) {
	startTime := time.Now()
	domain := strings.ToLower(queryInfo.Domain)

	// Fetch App Name for logging (and firewall)
	appName := ""
	if e.appResolver != nil {
		appName = e.appResolver.ResolveApp(
			int(queryInfo.SourcePort),
			[]byte(queryInfo.SourceIP),
			[]byte(queryInfo.DestIP),
			int(queryInfo.DestPort),
		)
	}

	// Firewall check (per-app blocking via Kotlin callback)
	if e.firewallChecker != nil && appName != "" {
		if e.firewallChecker.ShouldBlock(appName) {
			e.handleFirewallBlock(queryInfo, appName, startTime)
			return
		}
	}

	// SafeSearch check
	ssResult := e.safeSearch.Check(domain, queryInfo.QueryType)
	if ssResult.Action == ActionRedirect {
		if e.handleSafeSearchRedirect(queryInfo, ssResult.RedirectDomain, appName, startTime) {
			return
		}
		// If redirect IP resolution failed, fall through to normal resolution
	}

	// YouTube restricted mode check
	if isYT, ytDomain := e.safeSearch.CheckYouTube(domain, queryInfo.QueryType); isYT {
		if e.handleSafeSearchRedirect(queryInfo, ytDomain, appName, startTime) {
			return
		}
	}

	// Fast Native Go Domain blocking check via Mmap Trie
	if e.secTrie != nil && e.secTrie.ContainsOrParent(domain) {
		e.handleBlockedDomain(queryInfo, "security", appName, startTime)
		return
	}
	if e.adTrie != nil && e.adTrie.ContainsOrParent(domain) {
		e.handleBlockedDomain(queryInfo, "filter_list", appName, startTime)
		return
	}

	// Fallback/Custom Domain blocking check (via Kotlin callback)
	// This captures custom block/allow rules that aren't in the trie.
	if e.domainChecker != nil && e.domainChecker.IsBlocked(domain) {
		blockedBy := e.domainChecker.GetBlockReason(domain)
		e.handleBlockedDomain(queryInfo, blockedBy, appName, startTime)
		return
	}

	// Forward to upstream DNS
	e.handleForward(queryInfo, appName, startTime)
}

// handleSafeSearchRedirect handles a SafeSearch/YouTube redirect.
func (e *Engine) handleSafeSearchRedirect(queryInfo *DNSQueryInfo, redirectDomain, appName string, startTime time.Time) bool {
	// Check cache first
	ip := e.safeSearch.GetCachedIP(redirectDomain)
	if ip == nil {
		// Lazy resolve
		var err error
		ip, err = e.resolver.ResolveARecord(redirectDomain, e.primaryDNS)
		if err != nil {
			logf("SafeSearch resolve failed for %s: %v", redirectDomain, err)
			return false
		}
		e.safeSearch.CacheIP(redirectDomain, ip)
		logf("SafeSearch resolved: %s → %s", redirectDomain, ip.String())
	}

	response := BuildRedirectResponse(queryInfo, ip)
	e.writeToTUN(response)
	e.totalQueries.Add(1)

	elapsed := time.Since(startTime).Milliseconds()
	e.notifyLog(queryInfo.Domain, false, queryInfo.QueryType, elapsed, appName, ip.String(), "")
	return true
}

// handleFirewallBlock handles a DNS query blocked by the per-app firewall.
func (e *Engine) handleFirewallBlock(queryInfo *DNSQueryInfo, appName string, startTime time.Time) {
	var response []byte
	switch e.responseType {
	case ResponseNXDomain:
		response = BuildNXDomainResponse(queryInfo)
	case ResponseRefused:
		response = BuildRefusedResponse(queryInfo)
	default:
		response = BuildBlockedResponse(queryInfo)
	}

	e.writeToTUN(response)
	e.totalQueries.Add(1)
	e.blockedQueries.Add(1)

	elapsed := time.Since(startTime).Milliseconds()
	logf("BLOCKED: %s (by: firewall, app: %s)", queryInfo.Domain, appName)
	e.notifyLog(queryInfo.Domain, true, queryInfo.QueryType, elapsed, appName, "", "firewall")
}

// handleBlockedDomain handles a blocked domain.
func (e *Engine) handleBlockedDomain(queryInfo *DNSQueryInfo, blockedBy, appName string, startTime time.Time) {
	var response []byte
	switch e.responseType {
	case ResponseNXDomain:
		response = BuildNXDomainResponse(queryInfo)
	case ResponseRefused:
		response = BuildRefusedResponse(queryInfo)
	default:
		response = BuildBlockedResponse(queryInfo)
	}

	e.writeToTUN(response)
	e.totalQueries.Add(1)
	e.blockedQueries.Add(1)

	elapsed := time.Since(startTime).Milliseconds()
	logf("BLOCKED: %s (by: %s, app: %s)", queryInfo.Domain, blockedBy, appName)
	e.notifyLog(queryInfo.Domain, true, queryInfo.QueryType, elapsed, appName, "", blockedBy)
}

// handleForward forwards a DNS query to upstream and writes the response.
func (e *Engine) handleForward(queryInfo *DNSQueryInfo, appName string, startTime time.Time) {
	resp, err := e.resolver.Resolve(queryInfo.RawDNSPayload)
	if err != nil {
		logf("DNS resolve failed for %s: %v", queryInfo.Domain, err)
		servfail := BuildServfailResponse(queryInfo)
		e.writeToTUN(servfail)
		e.totalQueries.Add(1)

		elapsed := time.Since(startTime).Milliseconds()
		e.notifyLog(queryInfo.Domain, false, queryInfo.QueryType, elapsed, appName, "", "")
		return
	}

	response := BuildForwardedResponse(queryInfo, resp)
	e.writeToTUN(response)
	e.totalQueries.Add(1)

	elapsed := time.Since(startTime).Milliseconds()
	e.notifyLog(queryInfo.Domain, false, queryInfo.QueryType, elapsed, appName, "", "")
}

// writeToTUN writes a packet to the TUN device.
func (e *Engine) writeToTUN(data []byte) {
	e.mu.Lock()
	f := e.tunFile
	e.mu.Unlock()

	if f == nil {
		return
	}
	if _, err := f.Write(data); err != nil {
		logf("TUN write error: %v", err)
	}
}

// notifyLog sends a DNS query event to the Kotlin callback.
func (e *Engine) notifyLog(domain string, blocked bool, queryType uint16, responseTimeMs int64, appName, resolvedIP, blockedBy string) {
	if e.logCallback != nil {
		e.logCallback.OnDNSQuery(domain, blocked, int(queryType), responseTimeMs, appName, resolvedIP, blockedBy)
	}
}

// logf logs a message (will appear in Android logcat via stderr).
func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf("[BlockAds/Go] "+format, args...)
	fmt.Fprintln(os.Stderr, msg)
}

// ResolveHostForProtection resolves a hostname to an IP address.
// Used by Kotlin to bootstrap DNS server hostname resolution.
func ResolveHostForProtection(hostname string) string {
	ips, err := net.LookupHost(hostname)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}
