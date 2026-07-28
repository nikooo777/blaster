package valve

import (
	"testing"
	"time"
)

func TestParsePlayerReplyPreservesFractionalConnectionTime(t *testing.T) {
	data := []byte{
		0xff, 0xff, 0xff, 0xff,
		S2A_PLAYER,
		0x01,
		0x00,
		'A', 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xa0, 0x3f,
	}
	players := make([]Player, 0)
	querier := &ServerQuerier{}

	err := querier.parsePlayerReply(data, &players)

	if err != nil {
		t.Fatalf("parse player reply: %v", err)
	}
	if len(players) != 1 {
		t.Fatalf("expected one player, got %d", len(players))
	}
	if players[0].ConnectionTime != 1250*time.Millisecond {
		t.Fatalf(
			"expected fractional connection time %s, got %s",
			1250*time.Millisecond,
			players[0].ConnectionTime,
		)
	}
}
