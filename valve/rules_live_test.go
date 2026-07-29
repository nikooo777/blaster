//go:build liveverify
// +build liveverify

package valve

import (
	"os"
	"testing"
	"time"
)

func TestLiveRulesQuery(t *testing.T) {
	address := os.Getenv("LIVE_SERVER_ADDRESS")
	if address == "" {
		t.Skip("LIVE_SERVER_ADDRESS is not set")
	}

	querier, err := NewServerQuerier(address, 3*time.Second)
	if err != nil {
		t.Fatalf("create querier for %s: %v", address, err)
	}
	defer querier.Close()

	info, err := querier.QueryInfo()
	if err != nil {
		t.Fatalf("query info from %s: %v", address, err)
	}
	rules, err := querier.QueryRules()
	if err != nil {
		t.Fatalf("query rules from %s: %v", address, err)
	}
	if len(rules) == 0 {
		t.Fatalf("query rules from %s returned no rules", address)
	}

	t.Logf(
		"server=%s name=%q map=%q rules=%d",
		address,
		info.Name,
		info.MapName,
		len(rules),
	)
}
