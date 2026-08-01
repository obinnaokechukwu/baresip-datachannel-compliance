package main

import (
	"strings"
	"testing"
)

func TestRelayOnlySDPRemovesNonRelayCandidates(t *testing.T) {
	input := strings.Join([]string{
		"v=0\r",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r",
		"a=candidate:1 1 udp 1 10.0.0.5 5000 typ host\r",
		"a=candidate:2 1 udp 1 203.0.113.5 6000 typ srflx raddr 10.0.0.5 rport 5000\r",
		"a=candidate:3 1 udp 1 192.0.2.5 7000 typ relay raddr 10.0.0.5 rport 5000\r",
		"a=end-of-candidates\r",
		"",
	}, "\n")

	actual := relayOnlySDP(input)

	if strings.Contains(actual, " typ host") ||
		strings.Contains(actual, " typ srflx") {
		t.Fatalf("non-relay candidate survived: %q", actual)
	}
	if !strings.Contains(actual, " typ relay ") {
		t.Fatalf("relay candidate was removed: %q", actual)
	}
	if !strings.HasSuffix(actual, "a=end-of-candidates\r\n") {
		t.Fatalf("SDP framing changed: %q", actual)
	}
}
