// Package intel builds per-IP behavioral profiles from packet streams,
// runs heuristic detectors over them, and produces findings, narratives,
// and cross-references between nmap devices and observed traffic.
package intel

// Detection thresholds. Minimum confidence at which a detector emits a
// Finding; values below this are considered noise.
const (
	FindingThreshold       = 0.35 // most detectors
	BotThreshold           = 0.40 // periodic behavior alone isn't enough signal
	MinPacketsForDetection = 8    // below this results are meaningless
)

// Browser detector.
const (
	BrowserHTTPSMin       = 15 // HTTPS connections suggesting browsing
	BrowserDomainsMin     = 20 // unique resolved domains
	BrowserSrcPortsMin    = 25 // ephemeral source ports opened
	BrowserCDNHitsMin     = 3  // known browser CDN contacts required
	BrowserPortEntropyMin = 2.5
	BrowserDestIPsMin     = 10
)

// Bot / beacon detectors.
const (
	BotMinPackets         = 15
	BotIntervalNoiseFloor = 0.01
	BotMinSamples         = 5
	BotPrecisionCV        = 0.1
	BotPrecisionMean      = 0.5
	BotRegularCV          = 0.2
	BotRegularMean        = 1.0
	BotAutocorrMin        = 0.7
	BotMonotonicPortPct   = 0.85
	BotMonotonicPortMin   = 30
	BotLowDNSDomains      = 2
	BotLowDNSOutbound     = 40
	BotBurstMin           = 0.0
	BotBurstMax           = 0.3

	BeaconIntervalNoiseFloor = 0.1
	BeaconMinSamples         = 10
	BeaconMinMean            = 0.5
	BeaconTightCV            = 0.05
	BeaconTightMean          = 5.0
	BeaconJitterCVMin        = 0.05
	BeaconJitterCVMax        = 0.25
	BeaconJitterMean         = 10.0

	C2IntervalNoiseFloor = 0.5
	C2MinSamples         = 8
	C2RegularCV          = 0.15
	C2RegularMean        = 5.0
	C2JitterCVMin        = 0.05
	C2JitterCVMax        = 0.30
	C2JitterMean         = 10.0
	C2SmallPayloadMax    = 8.0
)

// Server detector.
const (
	ServerClientsMin      = 8
	ServerInboundRatio    = 2.0
	ServerDestPortsMin    = 15
	ServerLongSessionSecs = 30.0
	ServerLongSessionsMin = 3
)

// IoT detector.
const (
	IoTMaxDestIPs        = 4
	IoTMaxPPS            = 3.0
	IoTMaxDNS            = 5
	IoTHeartbeatBurstMin = 0.0
	IoTHeartbeatBurstMax = 0.4
)

// DNS profiler detector.
const (
	DNSQpsHigh          = 8.0
	DNSDomainsHigh      = 60
	DNSSingleLabelsHigh = 10
)

// Scanner detector.
const (
	ScannerPortThreshold   = 20
	ScannerHostThreshold   = 15
	ScannerPktsPerHost     = 2.0
	ScannerOutboundMin     = 80
	ScannerResponseRatio   = 8.0
	ScannerSequentialRatio = 0.5
)

// Streaming detector.
const (
	StreamMinDuration       = 10.0
	StreamSustainedPkts     = 200
	StreamSustainedDuration = 30.0
	StreamUDPDominance      = 2
	StreamMinUDP            = 30
	StreamHighPPS           = 30.0
)

// VPN detector.
const (
	VPNMaxDestIPs         = 2
	VPNMinPackets         = 100
	VPNTunnelRatio        = 0.9
	VPNTunnelMin          = 50
	VPNUniformVarianceMax = 1000.0
)

// Tor detector.
const (
	TorRelayClientsMin = 10
	TorRelayPacketsMin = 50
	TorCircuitDuration = 60.0
	TorCircuitsMin     = 5
)

// Game detector.
const (
	GameBurstMin = 0.5
	GamePPSMin   = 10.0
	GamePPSMax   = 200.0
)

// Lateral movement detector.
const (
	LateralMinInternalHosts = 4
	LateralMinMgmtPorts     = 3
	LateralInternalRatio    = 0.6
	LateralOverlapMin       = 2
	LateralScanRate         = 0.5
)

// Data exfiltration detector.
const (
	ExfilOutboundRatio     = 8.0
	ExfilMinOutbound       = 50
	ExfilSingleDestPct     = 0.85
	ExfilSingleDestMin     = 40
	ExfilLowDNSDomains     = 3
	ExfilLowDNSOutbound    = 60
	ExfilSustainedDuration = 60.0
	ExfilSustainedOutbound = 100
)

// Network recon detector.
const (
	ReconMinMgmtPorts     = 3
	ReconMinInternalHosts = 5
	ReconMaxPktsPerHost   = 5.0
)

// Printer/IoT detector.
const (
	PrinterMaxPPS = 2.0
)

// Profile builder.
const (
	MTUWeb            = 1500
	MTUSmall          = 64
	PrivilegedPortMax = 1024
	EphemeralPortMin  = 49152
	MinBinsForBurst   = 3
)
