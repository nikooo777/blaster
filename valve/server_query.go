// vim: set ts=4 sw=4 tw=99 noet:
//
// Blaster (C) Copyright 2014 AlliedModders LLC
// Licensed under the GNU General Public License, version 3 or higher.
// See LICENSE.txt for more details.
package valve

import (
	"bytes"
	"compress/bzip2"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"time"
)

var ErrBadPacketHeader = errors.New("bad packet header")
var ErrMistakenReply = errors.New("mistaken reply")
var ErrUnknownInfoVersion = errors.New("unknown A2S_INFO version")
var ErrImmediateRulesReply = errors.New("immediate rules reply")
var ErrBadChallengeResponse = errors.New("bad challenge response")
var ErrUnknownGameEngine = errors.New("must query A2S_INFO first")
var ErrDuplicatePacket = errors.New("received duplicate numbered packets")
var ErrBadPacketNumber = errors.New("packet number is out of sequence")
var ErrConfusedChallengeReply = errors.New("challenge reply is for the wrong query")
var ErrBadRulesReply = errors.New("bad rules reply")
var ErrWrongBz2Size = errors.New("bad bz2 decompression size")
var ErrWrongBz2Checksum = errors.New("bad bz2 checksum")
var ErrInvalidRulesQueryLimits = errors.New("invalid rules query limits")
var ErrRulesPacketLimit = errors.New("rules packet limit exceeded")
var ErrRulesPayloadLimit = errors.New("rules payload limit exceeded")
var ErrRulesCountLimit = errors.New("rules count limit exceeded")
var ErrRulesStringLimit = errors.New("rules string limit exceeded")
var ErrDuplicateRule = errors.New("duplicate rule")
var ErrTruncatedRulesReply = errors.New("truncated rules reply")
var ErrTrailingRulesData = errors.New("trailing rules data")
var ErrMismatchedPacket = errors.New("mismatched split packet")

const (
	defaultRulesTotalTimeout         = 5 * time.Second
	defaultRulesMaxPackets           = 32
	defaultRulesMaxPayloadBytes      = 64 * 1024
	defaultRulesMaxDecompressedBytes = 64 * 1024
	defaultRulesMaxRules             = 512
	defaultRulesMaxKeyBytes          = 256
	defaultRulesMaxValueBytes        = 4 * 1024
	hardRulesMaxTotalTimeout         = 30 * time.Second
	hardRulesMaxPackets              = 64
	hardRulesMaxPayloadBytes         = 1024 * 1024
	hardRulesMaxDecompressedBytes    = 1024 * 1024
	hardRulesMaxRules                = 4096
	hardRulesMaxKeyBytes             = 1024
	hardRulesMaxValueBytes           = 64 * 1024
	maxInfoChallenges                = 7
)

type RulesQueryLimits struct {
	TotalTimeout         time.Duration
	MaxPackets           int
	MaxPayloadBytes      int
	MaxDecompressedBytes int
	MaxRules             int
	MaxKeyBytes          int
	MaxValueBytes        int
}

func DefaultRulesQueryLimits(timeout time.Duration) RulesQueryLimits {
	if timeout <= 0 {
		timeout = defaultRulesTotalTimeout
	} else if timeout > hardRulesMaxTotalTimeout {
		timeout = hardRulesMaxTotalTimeout
	}
	return RulesQueryLimits{
		TotalTimeout:         timeout,
		MaxPackets:           defaultRulesMaxPackets,
		MaxPayloadBytes:      defaultRulesMaxPayloadBytes,
		MaxDecompressedBytes: defaultRulesMaxDecompressedBytes,
		MaxRules:             defaultRulesMaxRules,
		MaxKeyBytes:          defaultRulesMaxKeyBytes,
		MaxValueBytes:        defaultRulesMaxValueBytes,
	}
}

func validateRulesQueryLimits(limits RulesQueryLimits) error {
	if limits.TotalTimeout <= 0 ||
		limits.TotalTimeout > hardRulesMaxTotalTimeout ||
		limits.MaxPackets <= 0 ||
		limits.MaxPackets > hardRulesMaxPackets ||
		limits.MaxPayloadBytes <= 0 ||
		limits.MaxPayloadBytes > hardRulesMaxPayloadBytes ||
		limits.MaxDecompressedBytes <= 0 ||
		limits.MaxDecompressedBytes > hardRulesMaxDecompressedBytes ||
		limits.MaxRules <= 0 ||
		limits.MaxRules > hardRulesMaxRules ||
		limits.MaxKeyBytes <= 0 ||
		limits.MaxKeyBytes > hardRulesMaxKeyBytes ||
		limits.MaxValueBytes <= 0 ||
		limits.MaxValueBytes > hardRulesMaxValueBytes {
		return ErrInvalidRulesQueryLimits
	}
	return nil
}

// A ServerQuerier is used to issue A2S queries against an HL1/HL2 server.
type ServerQuerier struct {
	socket  *UdpSocket
	timeout time.Duration
	info    *ServerInfo
}

// Create a new server querying object.
func NewServerQuerier(hostAndPort string, timeout time.Duration) (*ServerQuerier, error) {
	socket, err := NewUdpSocket(hostAndPort, timeout)
	if err != nil {
		return nil, err
	}
	return &ServerQuerier{
		socket:  socket,
		timeout: timeout,
	}, nil
}

// Close the socket used to query.
func (this *ServerQuerier) Close() {
	this.socket.Close()
}

// Query a server's info via A2S_INFO.
func (this *ServerQuerier) QueryInfo() (*ServerInfo, error) {
	this.info = &ServerInfo{
		Address: this.socket.RemoteAddr().String(),
	}

	err := Try(func() error {
		return this.a2s_info(this.info)
	})
	if err != nil && err != ErrMistakenReply {
		return nil, err
	}

	// Mysteriously, Half-Life 1 servers will often reply to an A2S_INFO with
	// two extra packets: A2S_PLAYERS and then a newer A2S_INFO. We peek for
	// up to three extra packets with a very small timeout.
	if err == ErrMistakenReply || this.info.InfoVersion == S2A_INFO_GOLDSRC {
		err := Try(func() error {
			return this.check_bad_a2s_info(this.info)
		})
		if err == nil {
			return this.info, nil
		}
	}

	if err != nil {
		return nil, err
	}
	return this.info, nil
}

func (this *ServerQuerier) check_bad_a2s_info(info *ServerInfo) error {
	this.socket.SetTimeout(time.Millisecond * 250)
	defer this.socket.SetTimeout(this.timeout)

	data1, err := this.socket.Recv()
	if err != nil {
		return err
	}

	data2, err := this.socket.Recv()
	if err != nil {
		return err
	}

	// Try to decode either packet as an A2S_INFO.
	if this.parse_a2s_info_reply(this.info, data1) == nil {
		return nil
	}
	return this.parse_a2s_info_reply(this.info, data2)
}

func (this *ServerQuerier) a2s_info(info *ServerInfo) error {
	var packet PacketBuilder
	packet.WriteBytes([]byte{0xff, 0xff, 0xff, 0xff, A2S_INFO})
	packet.WriteCString("Source Engine Query")
	if err := this.socket.Send(packet.Bytes()); err != nil {
		return err
	}

	data, err := this.socket.Recv()
	if err != nil {
		return err
	}

	// The newer protocol requires A2S_INFO requests to contain a challenge,
	// servers that expected a challenge will have sent us a S2C_CHALLENGE response instead.
	// Some servers send several challenges in a row, so re-send the query with each one.
	for range maxInfoChallenges {
		if len(data) < 5 || data[4] != S2C_CHALLENGE {
			break
		}
		if len(data) < 9 {
			return ErrBadChallengeResponse
		}

		packet.Reset()
		packet.WriteBytes([]byte{0xff, 0xff, 0xff, 0xff, A2S_INFO})
		packet.WriteCString("Source Engine Query")
		packet.WriteBytes(data[5:9])
		err = this.socket.Send(packet.Bytes())
		if err != nil {
			return err
		}

		data, err = this.socket.Recv()
		if err != nil {
			return err
		}
	}

	return this.parse_a2s_info_reply(info, data)
}

func (this *ServerQuerier) parse_a2s_info_reply(info *ServerInfo, data []byte) error {
	reader := NewPacketReader(data)
	if reader.ReadInt32() != -1 {
		return ErrBadPacketHeader
	}

	info.InfoVersion = reader.ReadUint8()
	switch info.InfoVersion {
	case S2A_PLAYER:
		// Non-steam servers seem to reply with a corrupted packet. If we send
		// the query again, we often get the right thing, so propagate a special
		// error up.
		return ErrMistakenReply
	case S2A_INFO_SOURCE:
		this.parseNewInfo(reader, info)
	case S2A_INFO_GOLDSRC:
		this.parseOldInfo(reader, info)
	default:
		return ErrUnknownInfoVersion
	}
	return nil
}

func (this *ServerQuerier) parseNewInfo(reader *PacketReader, info *ServerInfo) {
	info.Protocol = reader.ReadUint8()
	info.Name = reader.ReadString()
	info.MapName = reader.ReadString()
	info.Folder = reader.ReadString()
	info.Game = reader.ReadString()

	// This gets extended later, potentially.
	appId := AppId(reader.ReadUint16())

	info.Players = reader.ReadUint8()
	info.MaxPlayers = reader.ReadUint8()
	info.Bots = reader.ReadUint8()

	serverType := reader.ReadUint8()
	switch serverType {
	case uint8('l'):
		info.Type = ServerType_Listen
	case uint8('d'):
		info.Type = ServerType_Dedicated
	default:
		info.Type = ServerType_Unknown
	}

	serverOS := reader.ReadUint8()
	switch serverOS {
	case uint8('l'):
		info.OS = ServerOS_Linux
	case uint8('w'):
		info.OS = ServerOS_Windows
	case uint8('m'):
		info.OS = ServerOS_Mac
	default:
		info.OS = ServerOS_Unknown
	}

	info.Visibility = reader.ReadUint8()
	info.Vac = reader.ReadUint8()

	// Read TheShip information.
	if AppId(appId) == App_TheShip {
		info.TheShip = &TheShipInfo{}
		info.TheShip.Mode = reader.ReadUint8()
		info.TheShip.Witnesses = reader.ReadUint8()
		info.TheShip.Duration = reader.ReadUint8()
	}

	info.Ext = &ExtendedInfo{
		AppId: appId,
	}

	// Start reading extended information.
	info.Ext.GameVersion = reader.ReadString()
	if !reader.More() {
		return
	}

	edf := reader.ReadUint8()
	if (edf & 0x80) != 0 {
		info.Ext.Port = reader.ReadUint16()
	}
	if (edf & 0x10) != 0 {
		info.Ext.SteamId = reader.ReadUint64()
	}
	if (edf & 0x40) != 0 {
		info.SpecTv = &SpecTvInfo{}
		info.SpecTv.Port = reader.ReadUint16()
		info.SpecTv.Name = reader.ReadString()
	}
	if (edf & 0x20) != 0 {
		info.Ext.GameModeDescription = reader.ReadString()
	}
	if (edf & 0x01) != 0 {
		gameId := reader.ReadUint64()

		// bits 0-23: true app id (original could be truncated)
		// bits 24-31: type
		// bits 32-63: mod id
		info.Ext.AppId = AppId(gameId & uint64(0xffffffff))
		info.Ext.GameId = gameId
	}
}

func (this *ServerQuerier) parseOldInfo(reader *PacketReader, info *ServerInfo) {
	info.Address = reader.ReadString()
	info.Name = reader.ReadString()
	info.MapName = reader.ReadString()
	info.Folder = reader.ReadString()
	info.Game = reader.ReadString()
	info.Players = reader.ReadUint8()
	info.MaxPlayers = reader.ReadUint8()
	info.Protocol = reader.ReadUint8()

	serverType := reader.ReadUint8()
	switch serverType {
	case uint8('l'):
		info.Type = ServerType_Listen
	case uint8('d'):
		info.Type = ServerType_Dedicated
	default:
		info.Type = ServerType_Unknown
	}

	serverOS := reader.ReadUint8()
	switch serverOS {
	case uint8('l'):
		info.OS = ServerOS_Linux
	case uint8('w'):
		info.OS = ServerOS_Windows
	default:
		info.OS = ServerOS_Unknown
	}

	info.Visibility = reader.ReadUint8()

	isMod := reader.ReadUint8()
	if isMod == 1 {
		info.Mod = &ModInfo{}
		info.Mod.Url = reader.ReadString()
		info.Mod.DwlUrl = reader.ReadString()
		reader.ReadUint8() // Ignore a null byte.
		info.Mod.Version = reader.ReadUint32()
		info.Mod.Size = reader.ReadUint32()
		info.Mod.Type = reader.ReadUint8()
		info.Mod.Dll = reader.ReadUint8()
	}

	info.Vac = reader.ReadUint8()
	info.Bots = reader.ReadUint8()
}

// Send an A2S_RULES query to the server. This returns a mapping of cvar names
// to values.
func (this *ServerQuerier) QueryRules() (map[string]string, error) {
	return this.QueryRulesWithLimits(DefaultRulesQueryLimits(this.timeout))
}

func (this *ServerQuerier) QueryRulesWithLimits(
	limits RulesQueryLimits,
) (map[string]string, error) {
	err := validateRulesQueryLimits(limits)
	if err != nil {
		return nil, err
	}
	err = this.socket.setAbsoluteDeadline(time.Now().Add(limits.TotalTimeout))
	if err != nil {
		return nil, err
	}
	defer this.socket.clearAbsoluteDeadline()

	var rules map[string]string
	err = Try(func() error {
		rules, err = this.queryRules(limits)
		return err
	})
	return rules, err
}

func (this *ServerQuerier) queryRules(
	limits RulesQueryLimits,
) (map[string]string, error) {
	rechallenges := 0
	data, err := this.a2s_rules()
	for err == ErrConfusedChallengeReply && rechallenges < 3 {
		data, err = this.a2s_rules()
		rechallenges++
	}

	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, ErrBadPacketHeader
	}

	switch int32(binary.LittleEndian.Uint32(data)) {
	case -1:
		return this.processRules(data, false, limits)
	case -2:
		full, compressed, err := this.waitForMultiPacketReplyWithLimits(
			data,
			multiPacketLimits{
				maxPackets:      limits.MaxPackets,
				maxPayloadBytes: limits.MaxPayloadBytes,
			},
		)
		if err != nil {
			return nil, err
		}
		return this.processRules(full, compressed, limits)
	default:
		return nil, ErrBadPacketHeader
	}
}

func (this *ServerQuerier) a2s_rules() ([]byte, error) {
	data := []byte{
		0xff, 0xff, 0xff, 0xff,
		A2S_RULES,
		0xff, 0xff, 0xff, 0xff,
	}
	if err := this.socket.Send(data); err != nil {
		return nil, err
	}

	data, err := this.socket.Recv()
	if err != nil {
		return nil, err
	}
	if len(data) < 5 {
		return nil, ErrBadPacketHeader
	}

	switch int32(binary.LittleEndian.Uint32(data[0:4])) {
	case -2:
		// AgeOfChivalry (appid 17510 had an instance of immediately reporting
		// a rules reply in response to a challenge. Maybe in a rare case the
		// server comes up with a -1 challenge?
		return data, nil
	case -1:
		// Ok, continue.
	default:
		return nil, ErrBadPacketHeader
	}

	switch data[4] {
	case S2A_RULES:
		return data, nil
	case S2A_INFO_SOURCE, S2A_PLAYER:
		// Some servers reply with the wrong kind of query. For these, we retry.
		return nil, ErrConfusedChallengeReply
	case S2C_CHALLENGE:
		if len(data) < 9 {
			return nil, ErrBadChallengeResponse
		}
	default:
		return nil, ErrBadChallengeResponse
	}

	// Send the rules query now that we've got a challenge sequence.
	reply := []byte{
		0xff, 0xff, 0xff, 0xff,
		A2S_RULES,
		data[5], data[6], data[7], data[8],
	}
	if err := this.socket.Send(reply); err != nil {
		return nil, err
	}
	return this.socket.Recv()
}

func (this *ServerQuerier) a2s_players() ([]byte, error) {
	// Initial A2S_PLAYER query packet without a challenge
	data := []byte{0xff, 0xff, 0xff, 0xff, A2S_PLAYER, 0xff, 0xff, 0xff, 0xff}
	if err := this.socket.Send(data); err != nil {
		return nil, err
	}

	// Receive the initial response
	response, err := this.socket.Recv()
	if err != nil {
		return nil, err
	}

	// Check if the response header is valid
	if len(response) < 5 || int32(binary.LittleEndian.Uint32(response[0:4])) != -1 {
		return nil, ErrBadPacketHeader
	}

	// Handle challenge response if received
	if response[4] == S2C_CHALLENGE {
		if len(response) < 9 {
			return nil, ErrBadChallengeResponse
		}

		// Extract the challenge number from the response (bytes 5-8)
		challenge := response[5:9]

		// Resend the query with the challenge
		packet := PacketBuilder{}
		packet.WriteBytes([]byte{0xff, 0xff, 0xff, 0xff, A2S_PLAYER})
		packet.WriteBytes(challenge)
		if err := this.socket.Send(packet.Bytes()); err != nil {
			return nil, err
		}

		// Receive the final response
		response, err = this.socket.Recv()
		if err != nil {
			return nil, err
		}
	}

	// Return the response data for further processing
	return response, nil
}

type MultiPacketHeader struct {
	// Size of the packet header itself.
	Size int

	// Packet sequence id.
	Id uint32

	// Packet number out of Total Packets.
	PacketNumber uint8

	// Total number of packets to receive.
	TotalPackets uint8

	// Packet size (0 if not present).
	PacketSize uint16

	// Compression information.
	Compressed bool

	Payload []byte
}

type multiPacketLimits struct {
	maxPackets      int
	maxPayloadBytes int
}

func (this *ServerQuerier) decodeMultiPacketHeader(
	data []byte,
) (*MultiPacketHeader, error) {
	if len(data) < 8 {
		return nil, ErrBadPacketHeader
	}
	reader := NewPacketReader(data)
	if reader.ReadInt32() != -2 {
		return nil, ErrBadPacketHeader
	}
	if this.info == nil {
		return nil, ErrUnknownGameEngine
	}

	header := &MultiPacketHeader{}
	header.Id = reader.ReadUint32()

	switch this.info.GameEngine() {
	case GOLDSRC:
		if len(data) < 9 {
			return nil, ErrBadPacketHeader
		}
		pkt := reader.ReadUint8()
		header.PacketNumber = (pkt >> 4) & 0xf
		header.TotalPackets = (pkt & 0xf)

	case SOURCE:
		if len(data) < 10 {
			return nil, ErrBadPacketHeader
		}
		header.Compressed = (header.Id & uint32(0x80000000)) != 0
		header.TotalPackets = reader.ReadUint8()
		header.PacketNumber = reader.ReadUint8()
		if !this.info.IsPreOrangeBox() {
			if len(data) < 12 {
				return nil, ErrBadPacketHeader
			}
			header.PacketSize = reader.ReadUint16()
		}

	default:
		return nil, ErrUnknownGameEngine
	}

	header.Size = reader.Pos()
	header.Payload = data[header.Size:]
	return header, nil
}

func (this *ServerQuerier) waitForMultiPacketReply(data []byte) ([]byte, bool, error) {
	return this.waitForMultiPacketReplyWithLimits(
		data,
		multiPacketLimits{
			maxPackets:      255,
			maxPayloadBytes: kMaxPacketSize * 255,
		},
	)
}

func (this *ServerQuerier) waitForMultiPacketReplyWithLimits(
	data []byte,
	limits multiPacketLimits,
) ([]byte, bool, error) {
	header, err := this.decodeMultiPacketHeader(data)
	if err != nil {
		return nil, false, err
	}
	if header.TotalPackets == 0 {
		return nil, false, ErrBadPacketNumber
	}
	if int(header.TotalPackets) > limits.maxPackets {
		return nil, false, ErrRulesPacketLimit
	}
	expectedID := header.Id
	expectedTotalPackets := header.TotalPackets
	expectedCompressed := header.Compressed
	expectedPacketSize := header.PacketSize
	packets := make([]*MultiPacketHeader, header.TotalPackets)
	received := 0
	fullSize := 0

	for {
		if header.Id != expectedID ||
			header.TotalPackets != expectedTotalPackets ||
			header.Compressed != expectedCompressed ||
			header.PacketSize != expectedPacketSize {
			return nil, false, ErrMismatchedPacket
		}
		if int(header.PacketNumber) >= len(packets) {
			return nil, false, ErrBadPacketNumber
		}
		if packets[header.PacketNumber] != nil {
			return nil, false, ErrDuplicatePacket
		}

		if len(header.Payload) > limits.maxPayloadBytes-fullSize {
			return nil, false, ErrRulesPayloadLimit
		}
		packets[header.PacketNumber] = header
		fullSize += len(header.Payload)
		received++

		if received == len(packets) {
			break
		}

		data, err := this.socket.Recv()
		if err != nil {
			return nil, false, err
		}

		header, err = this.decodeMultiPacketHeader(data)
		if err != nil {
			return nil, false, err
		}
	}

	payload := make([]byte, fullSize)
	cursor := 0
	for _, header := range packets {
		copy(payload[cursor:cursor+len(header.Payload)], header.Payload)
		cursor += len(header.Payload)
	}

	return payload, packets[0].Compressed, nil
}

func (this *ServerQuerier) processRules(
	data []byte,
	compressed bool,
	limits RulesQueryLimits,
) (map[string]string, error) {
	if len(data) > limits.MaxPayloadBytes {
		return nil, ErrRulesPayloadLimit
	}
	reader := NewPacketReader(data)

	if compressed {
		if len(data) < 8 {
			return nil, ErrTruncatedRulesReply
		}
		decompressedSize := reader.ReadUint32()
		checksum := reader.ReadUint32()
		if decompressedSize > uint32(limits.MaxDecompressedBytes) {
			return nil, ErrWrongBz2Size
		}

		bz2Reader := bzip2.NewReader(bytes.NewReader(data[reader.Pos():]))
		decompressed, err := io.ReadAll(io.LimitReader(
			bz2Reader,
			int64(decompressedSize)+1,
		))
		if err != nil {
			return nil, err
		}
		if len(decompressed) != int(decompressedSize) {
			return nil, ErrWrongBz2Size
		}
		if crc32.ChecksumIEEE(decompressed) != checksum {
			return nil, ErrWrongBz2Checksum
		}

		// Switch to the decompressed stream.
		data = decompressed
		reader = NewPacketReader(data)
	}

	if len(data) < 7 {
		return nil, ErrTruncatedRulesReply
	}
	if reader.ReadInt32() != -1 {
		return nil, ErrBadPacketHeader
	}
	if reader.ReadUint8() != S2A_RULES {
		return nil, ErrBadRulesReply
	}

	count := int(reader.ReadUint16())
	if count > limits.MaxRules {
		return nil, ErrRulesCountLimit
	}

	rules := make(map[string]string, count)
	for range count {
		key, err := readBoundedRuleString(reader, limits.MaxKeyBytes)
		if err != nil {
			return nil, err
		}
		value, err := readBoundedRuleString(reader, limits.MaxValueBytes)
		if err != nil {
			return nil, err
		}
		if _, exists := rules[key]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateRule, key)
		}
		rules[key] = value
	}
	if reader.More() {
		return nil, ErrTrailingRulesData
	}

	return rules, nil
}

func readBoundedRuleString(
	reader *PacketReader,
	maxBytes int,
) (string, error) {
	remaining := reader.buffer[reader.pos:]
	end := bytes.IndexByte(remaining, 0)
	if end < 0 {
		return "", ErrTruncatedRulesReply
	}
	if end > maxBytes {
		return "", ErrRulesStringLimit
	}
	value := string(remaining[:end])
	reader.pos += end + 1
	return value, nil
}

type Player struct {
	Id             uint8         `json:"id"`
	Name           string        `json:"name"`
	Score          int32         `json:"score"`
	ConnectionTime time.Duration `json:"connection_time"`
}

// QueryPlayers sends an A2S_PLAYER query to the CS:S server and returns a list of connected players.
// If server info is not yet fetched, it automatically calls QueryInfo() first.
func (this *ServerQuerier) QueryPlayers() ([]Player, error) {
	// Automatically fetch server info if not already present
	if this.info == nil {
		_, err := this.QueryInfo()
		if err != nil {
			return nil, fmt.Errorf("failed to auto-fetch server info: %w", err)
		}
	}

	var players []Player
	err := Try(func() error {
		// Get the raw response from a2s_players
		data, err := this.a2s_players()
		if err != nil {
			return err
		}
		if len(data) < 4 {
			return ErrBadPacketHeader
		}

		// Check the packet header to determine if it's single or multi-packet
		switch int32(binary.LittleEndian.Uint32(data[0:4])) {
		case -1:
			// Single packet reply
			return this.parsePlayerReply(data, &players)
		case -2:
			// Multi-packet reply
			fullData, compressed, err := this.waitForMultiPacketReply(data)
			if err != nil {
				return err
			}
			if compressed {
				return errors.New("compressed A2S_PLAYER responses are not supported")
			}
			return this.parsePlayerReply(fullData, &players)
		default:
			return ErrBadPacketHeader
		}
	})

	return players, err
}

// parsePlayerReply parses the A2S_PLAYER response data into a slice of Player structs for Source engine (CS:S).
func (this *ServerQuerier) parsePlayerReply(data []byte, players *[]Player) error {
	if len(data) < 6 {
		return errors.New("data too short for player response")
	}
	reader := NewPacketReader(data)

	// Validate header and response type
	if reader.ReadInt32() != -1 {
		return ErrBadPacketHeader
	}
	if reader.ReadUint8() != S2A_PLAYER {
		return errors.New("unexpected response type, expected S2A_PLAYER")
	}

	// Read number of players
	numPlayers := reader.ReadUint8()
	*players = make([]Player, numPlayers)

	// Parse each player's data (Source engine format)
	for i := 0; i < int(numPlayers); i++ {
		player := &(*players)[i]
		reader.ReadUint8() // The wire index is always 0, so use the position instead.
		player.Id = uint8(i)
		player.Name = reader.ReadString()
		player.Score = reader.ReadInt32() // 4-byte integer for Source engine
		playerTimeSeconds := reader.ReadFloat32()
		player.ConnectionTime = time.Duration(float64(playerTimeSeconds) * float64(time.Second))
	}

	return nil
}
