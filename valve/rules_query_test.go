package valve

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"testing"
	"time"
)

const rulesFixtureTimeout = 3 * time.Second

type rulesFixture struct {
	connection *net.UDPConn
	responses  [][]byte
	delays     []time.Duration
	done       chan error
}

func newRulesFixture(
	t *testing.T,
	responses [][]byte,
	delays []time.Duration,
) *rulesFixture {
	t.Helper()

	connection, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
	)
	if err != nil {
		t.Fatalf("listen for rules fixture: %v", err)
	}
	err = connection.SetDeadline(time.Now().Add(rulesFixtureTimeout))
	if err != nil {
		connection.Close()
		t.Fatalf("set rules fixture deadline: %v", err)
	}

	fixture := &rulesFixture{
		connection: connection,
		responses:  responses,
		delays:     delays,
		done:       make(chan error, 1),
	}
	go serveRulesFixture(fixture)
	return fixture
}

func serveRulesFixture(fixture *rulesFixture) {
	buffer := make([]byte, kMaxPacketSize)
	n, address, err := fixture.connection.ReadFromUDP(buffer)
	if err != nil {
		fixture.done <- err
		return
	}
	if n < 5 || buffer[4] != A2S_RULES {
		fixture.done <- errors.New("unexpected initial query")
		return
	}

	challenge := []byte{
		0xff, 0xff, 0xff, 0xff,
		S2C_CHALLENGE,
		0x01, 0x02, 0x03, 0x04,
	}
	_, err = fixture.connection.WriteToUDP(challenge, address)
	if err != nil {
		fixture.done <- err
		return
	}

	n, address, err = fixture.connection.ReadFromUDP(buffer)
	if err != nil {
		fixture.done <- err
		return
	}
	if n < 9 ||
		buffer[4] != A2S_RULES ||
		buffer[5] != challenge[5] ||
		buffer[6] != challenge[6] ||
		buffer[7] != challenge[7] ||
		buffer[8] != challenge[8] {
		fixture.done <- errors.New("unexpected challenged query")
		return
	}

	for index, response := range fixture.responses {
		if index < len(fixture.delays) {
			time.Sleep(fixture.delays[index])
		}
		_, err = fixture.connection.WriteToUDP(response, address)
		if err != nil {
			fixture.done <- err
			return
		}
	}
	fixture.done <- nil
}

func (fixture *rulesFixture) address() string {
	return fixture.connection.LocalAddr().String()
}

func (fixture *rulesFixture) wait(t *testing.T) {
	t.Helper()
	defer fixture.connection.Close()

	select {
	case err := <-fixture.done:
		if err != nil {
			t.Errorf("rules fixture: %v", err)
		}
	case <-time.After(rulesFixtureTimeout + time.Second):
		t.Errorf("rules fixture did not finish")
	}
}

func buildRulesPacket(count uint16, rules [][2]string) []byte {
	packet := make([]byte, 7)
	binary.LittleEndian.PutUint32(packet, uint32(0xffffffff))
	packet[4] = S2A_RULES
	binary.LittleEndian.PutUint16(packet[5:], count)
	for _, rule := range rules {
		packet = append(packet, []byte(rule[0])...)
		packet = append(packet, 0)
		packet = append(packet, []byte(rule[1])...)
		packet = append(packet, 0)
	}
	return packet
}

func buildSourceSplitPacket(
	id uint32,
	total uint8,
	number uint8,
	payload []byte,
) []byte {
	packet := make([]byte, 12)
	binary.LittleEndian.PutUint32(packet, uint32(0xfffffffe))
	binary.LittleEndian.PutUint32(packet[4:], id)
	packet[8] = total
	packet[9] = number
	binary.LittleEndian.PutUint16(packet[10:], kMaxPacketSize)
	return append(packet, payload...)
}

func buildCompressedRulesPacket() []byte {
	rules := buildRulesPacket(1, [][2]string{{"hostname", "fixture"}})
	compressed := []byte{
		0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26,
		0x53, 0x59, 0xdd, 0x31, 0xbe, 0xa5, 0x00, 0x00,
		0x0c, 0x45, 0x80, 0xe0, 0x00, 0x02, 0x00, 0x23,
		0x63, 0x9e, 0x40, 0x00, 0x00, 0xa0, 0x00, 0x31,
		0x43, 0x4d, 0x30, 0x00, 0x50, 0xc4, 0x36, 0xa3,
		0x1a, 0x85, 0x93, 0x0a, 0xa0, 0x79, 0x2c, 0xef,
		0x3d, 0xa9, 0xa2, 0xc4, 0xdc, 0x7c, 0x5d, 0xc9,
		0x14, 0xe1, 0x42, 0x43, 0x74, 0xc6, 0xfa, 0x94,
	}
	packet := make([]byte, 8)
	binary.LittleEndian.PutUint32(packet, uint32(len(rules)))
	binary.LittleEndian.PutUint32(packet[4:], crc32.ChecksumIEEE(rules))
	return append(packet, compressed...)
}

func sourceServerInfo() *ServerInfo {
	return &ServerInfo{
		InfoVersion: S2A_INFO_SOURCE,
		Protocol:    17,
		Ext: &ExtendedInfo{
			AppId: App_CSS,
		},
	}
}

func TestProcessRules(t *testing.T) {
	limits := DefaultRulesQueryLimits(time.Second)
	packet := buildRulesPacket(
		2,
		[][2]string{
			{"hostname", "test"},
			{"secure", "1"},
		},
	)
	querier := &ServerQuerier{}

	rules, err := querier.processRules(packet, false, limits)

	if err != nil {
		t.Fatalf("process rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected two rules, got %d", len(rules))
	}
	if rules["hostname"] != "test" {
		t.Fatalf("expected hostname rule, got %q", rules["hostname"])
	}
	if rules["secure"] != "1" {
		t.Fatalf("expected secure rule, got %q", rules["secure"])
	}
}

func TestProcessRulesRejectsMalformedReplies(t *testing.T) {
	defaultLimits := DefaultRulesQueryLimits(time.Second)
	shortKeyLimits := defaultLimits
	shortKeyLimits.MaxKeyBytes = 3
	shortValueLimits := defaultLimits
	shortValueLimits.MaxValueBytes = 3
	lowCountLimits := defaultLimits
	lowCountLimits.MaxRules = 1

	trailing := buildRulesPacket(1, [][2]string{{"a", "b"}})
	trailing = append(trailing, 0)

	tests := []struct {
		name       string
		packet     []byte
		limits     RulesQueryLimits
		expected   error
		compressed bool
	}{
		{
			name:     "truncated count",
			packet:   buildRulesPacket(2, [][2]string{{"a", "b"}}),
			limits:   defaultLimits,
			expected: ErrTruncatedRulesReply,
		},
		{
			name: "duplicate key",
			packet: buildRulesPacket(
				2,
				[][2]string{{"a", "b"}, {"a", "c"}},
			),
			limits:   defaultLimits,
			expected: ErrDuplicateRule,
		},
		{
			name:     "too many rules",
			packet:   buildRulesPacket(2, nil),
			limits:   lowCountLimits,
			expected: ErrRulesCountLimit,
		},
		{
			name:     "long key",
			packet:   buildRulesPacket(1, [][2]string{{"four", "b"}}),
			limits:   shortKeyLimits,
			expected: ErrRulesStringLimit,
		},
		{
			name:     "long value",
			packet:   buildRulesPacket(1, [][2]string{{"a", "four"}}),
			limits:   shortValueLimits,
			expected: ErrRulesStringLimit,
		},
		{
			name:     "trailing data",
			packet:   trailing,
			limits:   defaultLimits,
			expected: ErrTrailingRulesData,
		},
		{
			name:       "large decompressed size",
			packet:     []byte{0x01, 0x00, 0x01, 0x00, 0, 0, 0, 0},
			limits:     defaultLimits,
			expected:   ErrWrongBz2Size,
			compressed: true,
		},
	}

	querier := &ServerQuerier{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := querier.processRules(
				test.packet,
				test.compressed,
				test.limits,
			)

			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

func TestRulesQueryLimits(t *testing.T) {
	limits := DefaultRulesQueryLimits(0)
	if limits.TotalTimeout != defaultRulesTotalTimeout {
		t.Fatalf("expected default timeout, got %s", limits.TotalTimeout)
	}

	limits = DefaultRulesQueryLimits(time.Second)
	if limits.TotalTimeout != time.Second {
		t.Fatalf("expected requested timeout, got %s", limits.TotalTimeout)
	}

	limits = DefaultRulesQueryLimits(hardRulesMaxTotalTimeout + time.Second)
	if limits.TotalTimeout != hardRulesMaxTotalTimeout {
		t.Fatalf("expected capped timeout, got %s", limits.TotalTimeout)
	}

	err := validateRulesQueryLimits(RulesQueryLimits{})
	if !errors.Is(err, ErrInvalidRulesQueryLimits) {
		t.Fatalf("expected invalid limits error, got %v", err)
	}
}

func TestWaitForMultiPacketReplyRejectsInvalidFragments(t *testing.T) {
	querier := &ServerQuerier{info: sourceServerInfo()}
	limits := multiPacketLimits{
		maxPackets:      2,
		maxPayloadBytes: 10,
	}

	tests := []struct {
		name     string
		packet   []byte
		expected error
	}{
		{
			name:     "truncated header",
			packet:   []byte{0xfe, 0xff, 0xff, 0xff},
			expected: ErrBadPacketHeader,
		},
		{
			name:     "zero packets",
			packet:   buildSourceSplitPacket(1, 0, 0, nil),
			expected: ErrBadPacketNumber,
		},
		{
			name:     "packet limit",
			packet:   buildSourceSplitPacket(1, 3, 0, nil),
			expected: ErrRulesPacketLimit,
		},
		{
			name: "payload limit",
			packet: buildSourceSplitPacket(
				1,
				1,
				0,
				make([]byte, limits.maxPayloadBytes+1),
			),
			expected: ErrRulesPayloadLimit,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := querier.waitForMultiPacketReplyWithLimits(
				test.packet,
				limits,
			)

			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

func TestQueryRulesWithLimits(t *testing.T) {
	response := buildRulesPacket(1, [][2]string{{"hostname", "fixture"}})
	fixture := newRulesFixture(t, [][]byte{response}, nil)
	querier, err := NewServerQuerier(fixture.address(), time.Second)
	if err != nil {
		fixture.connection.Close()
		t.Fatalf("create querier: %v", err)
	}
	defer querier.Close()
	defer fixture.wait(t)

	rules, err := querier.QueryRulesWithLimits(
		DefaultRulesQueryLimits(time.Second),
	)

	if err != nil {
		t.Fatalf("query rules: %v", err)
	}
	if rules["hostname"] != "fixture" {
		t.Fatalf("expected fixture hostname, got %q", rules["hostname"])
	}
	if !querier.socket.absoluteDeadline.IsZero() {
		t.Fatalf("query deadline was not cleared")
	}
}

func TestQueryRulesWithCompressedFragments(t *testing.T) {
	response := buildCompressedRulesPacket()
	midpoint := len(response) / 2
	responses := [][]byte{
		buildSourceSplitPacket(
			0x80000001,
			2,
			0,
			response[:midpoint],
		),
		buildSourceSplitPacket(
			0x80000001,
			2,
			1,
			response[midpoint:],
		),
	}
	fixture := newRulesFixture(t, responses, nil)
	querier, err := NewServerQuerier(fixture.address(), time.Second)
	if err != nil {
		fixture.connection.Close()
		t.Fatalf("create querier: %v", err)
	}
	querier.info = sourceServerInfo()
	defer querier.Close()
	defer fixture.wait(t)

	rules, err := querier.QueryRulesWithLimits(
		DefaultRulesQueryLimits(time.Second),
	)

	if err != nil {
		t.Fatalf("query compressed rules: %v", err)
	}
	if rules["hostname"] != "fixture" {
		t.Fatalf("expected fixture hostname, got %q", rules["hostname"])
	}
}

func TestQueryRulesRejectsMismatchedFragments(t *testing.T) {
	response := buildRulesPacket(1, [][2]string{{"hostname", "fixture"}})
	midpoint := len(response) / 2
	responses := [][]byte{
		buildSourceSplitPacket(1, 2, 0, response[:midpoint]),
		buildSourceSplitPacket(2, 2, 1, response[midpoint:]),
	}
	fixture := newRulesFixture(t, responses, nil)
	querier, err := NewServerQuerier(fixture.address(), time.Second)
	if err != nil {
		fixture.connection.Close()
		t.Fatalf("create querier: %v", err)
	}
	querier.info = sourceServerInfo()
	defer querier.Close()
	defer fixture.wait(t)

	_, err = querier.QueryRulesWithLimits(
		DefaultRulesQueryLimits(time.Second),
	)

	if !errors.Is(err, ErrMismatchedPacket) {
		t.Fatalf("expected mismatched packet, got %v", err)
	}
}

func TestQueryRulesUsesAbsoluteDeadline(t *testing.T) {
	response := buildRulesPacket(1, [][2]string{{"hostname", "fixture"}})
	first := len(response) / 3
	second := first * 2
	responses := [][]byte{
		buildSourceSplitPacket(1, 3, 0, response[:first]),
		buildSourceSplitPacket(1, 3, 1, response[first:second]),
		buildSourceSplitPacket(1, 3, 2, response[second:]),
	}
	fixture := newRulesFixture(
		t,
		responses,
		[]time.Duration{0, 70 * time.Millisecond, 70 * time.Millisecond},
	)
	querier, err := NewServerQuerier(fixture.address(), time.Second)
	if err != nil {
		fixture.connection.Close()
		t.Fatalf("create querier: %v", err)
	}
	querier.info = sourceServerInfo()
	defer querier.Close()
	defer fixture.wait(t)

	limits := DefaultRulesQueryLimits(time.Second)
	limits.TotalTimeout = 100 * time.Millisecond
	_, err = querier.QueryRulesWithLimits(limits)

	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
}
