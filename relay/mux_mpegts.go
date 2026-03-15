package relay

import (
	"bytes"
	"encoding/binary"
)

const (
	tsPacketSize = 188
	tsSyncByte   = 0x47
	patPID       = 0x0000
	pmtPID       = 0x1000
	audioPID     = 0x0100
	videoPID     = 0x0101
	mp3StreamID  = 0xC0
	h264StreamID = 0xE0
	tsClockRate  = 90000 // 90kHz PTS clock
)

// TSMuxer creates MPEG-TS segments from audio and video frames.
type TSMuxer struct {
	audioContinuity uint8
	videoContinuity uint8
	patContinuity   uint8
	pmtContinuity   uint8
}

// NewTSMuxer creates a new MPEG-TS muxer.
func NewTSMuxer() *TSMuxer {
	return &TSMuxer{}
}

// MuxMP3Segment wraps MP3 audio data into a complete MPEG-TS segment.
// pts is the presentation timestamp in 90kHz units.
func (m *TSMuxer) MuxMP3Segment(mp3Data []byte, pts int64) []byte {
	var buf bytes.Buffer

	// 1. Write PAT
	m.writePAT(&buf)

	// 2. Write PMT
	m.writePMT(&buf)

	// 3. Write audio PES packets
	m.writeAudioPES(&buf, mp3Data, pts)

	return buf.Bytes()
}

// MuxAVSegment wraps audio and video data into a complete MPEG-TS segment.
// audioData is MP3 audio, videoData is H.264 Annex B data.
// audioPTS and videoPTS are presentation timestamps in 90kHz units.
func (m *TSMuxer) MuxAVSegment(audioData []byte, videoData []byte, audioPTS, videoPTS int64) []byte {
	var buf bytes.Buffer

	// Write PAT
	m.writePAT(&buf)

	// Write PMT (updated for A/V)
	m.writePMTAV(&buf)

	// Write video PES first (usually larger, keyframe-aligned)
	if len(videoData) > 0 {
		m.writeVideoPES(&buf, videoData, videoPTS)
	}

	// Write audio PES
	if len(audioData) > 0 {
		m.writeAudioPES(&buf, audioData, audioPTS)
	}

	return buf.Bytes()
}

func (m *TSMuxer) writePMTAV(buf *bytes.Buffer) {
	packet := make([]byte, tsPacketSize)

	packet[0] = tsSyncByte
	packet[1] = 0x40 | byte(pmtPID>>8)
	packet[2] = byte(pmtPID & 0xFF)
	packet[3] = 0x10 | (m.pmtContinuity & 0x0F)
	m.pmtContinuity++

	packet[4] = 0x00 // pointer field

	pmt := packet[5:]
	pmt[0] = 0x02 // table_id
	pmt[1] = 0xB0 // section_syntax_indicator
	pmt[2] = 23   // section_length (larger for A/V)
	pmt[3] = 0x00 // program_number high
	pmt[4] = 0x01 // program_number low
	pmt[5] = 0xC1 // version=0, current_next=1
	pmt[6] = 0x00 // section_number
	pmt[7] = 0x00 // last_section_number
	pmt[8] = 0xE0 | byte(videoPID>>8) // PCR PID = video
	pmt[9] = byte(videoPID & 0xFF)
	pmt[10] = 0xF0 // reserved + program_info_length high
	pmt[11] = 0x00 // program_info_length low

	// Video stream: H.264
	pmt[12] = 0x1B // stream_type = 0x1B (H.264)
	pmt[13] = 0xE0 | byte(videoPID>>8)
	pmt[14] = byte(videoPID & 0xFF)
	pmt[15] = 0xF0
	pmt[16] = 0x00

	// Audio stream: MP3
	pmt[17] = 0x03 // stream_type = 0x03 (MP3)
	pmt[18] = 0xE0 | byte(audioPID>>8)
	pmt[19] = byte(audioPID & 0xFF)
	pmt[20] = 0xF0
	pmt[21] = 0x00

	// CRC32
	crc := crc32MPEG2(pmt[0:22])
	binary.BigEndian.PutUint32(pmt[22:26], crc)

	for i := 5 + 26; i < tsPacketSize; i++ {
		packet[i] = 0xFF
	}

	buf.Write(packet)
}

func (m *TSMuxer) writeVideoPES(buf *bytes.Buffer, data []byte, pts int64) {
	pesHeader := buildPESHeader(h264StreamID, len(data), pts)
	payload := append(pesHeader, data...)

	offset := 0
	first := true
	for offset < len(payload) {
		packet := make([]byte, tsPacketSize)

		packet[0] = tsSyncByte
		pidHigh := byte(videoPID >> 8)
		if first {
			pidHigh |= 0x40
			first = false
		}
		packet[1] = pidHigh
		packet[2] = byte(videoPID & 0xFF)

		remaining := len(payload) - offset
		payloadCapacity := tsPacketSize - 4

		if remaining < payloadCapacity {
			stuffingLen := payloadCapacity - remaining - 2
			if stuffingLen < 0 {
				stuffingLen = 0
			}
			adaptLen := 1 + stuffingLen
			packet[3] = 0x30 | (m.videoContinuity & 0x0F)
			packet[4] = byte(adaptLen)
			packet[5] = 0x00
			for i := 0; i < stuffingLen; i++ {
				packet[6+i] = 0xFF
			}
			copy(packet[4+1+adaptLen:], payload[offset:])
			offset = len(payload)
		} else {
			packet[3] = 0x10 | (m.videoContinuity & 0x0F)
			copy(packet[4:], payload[offset:offset+payloadCapacity])
			offset += payloadCapacity
		}

		m.videoContinuity++
		buf.Write(packet)
	}
}

func (m *TSMuxer) writePAT(buf *bytes.Buffer) {
	packet := make([]byte, tsPacketSize)

	// TS header
	packet[0] = tsSyncByte
	packet[1] = 0x40 // payload_unit_start_indicator = 1, PID high bits = 0
	packet[2] = 0x00 // PID low bits = 0 (PAT)
	packet[3] = 0x10 | (m.patContinuity & 0x0F) // no adaptation, payload only
	m.patContinuity++

	// Pointer field (required when payload_unit_start_indicator=1)
	packet[4] = 0x00

	// PAT table
	pat := packet[5:]
	pat[0] = 0x00 // table_id = 0 (PAT)
	pat[1] = 0xB0 // section_syntax_indicator=1, reserved
	pat[2] = 13   // section_length (remaining bytes including CRC)
	pat[3] = 0x00 // transport_stream_id high
	pat[4] = 0x01 // transport_stream_id low
	pat[5] = 0xC1 // version=0, current_next=1
	pat[6] = 0x00 // section_number
	pat[7] = 0x00 // last_section_number
	// Program entry: program_number=1, PMT PID=0x1000
	pat[8] = 0x00                       // program_number high
	pat[9] = 0x01                       // program_number low
	pat[10] = 0xE0 | byte(pmtPID>>8)   // reserved + PID high
	pat[11] = byte(pmtPID & 0xFF)      // PID low

	// CRC32
	crc := crc32MPEG2(pat[0:12])
	binary.BigEndian.PutUint32(pat[12:16], crc)

	// Fill rest with 0xFF
	for i := 5 + 16; i < tsPacketSize; i++ {
		packet[i] = 0xFF
	}

	buf.Write(packet)
}

func (m *TSMuxer) writePMT(buf *bytes.Buffer) {
	packet := make([]byte, tsPacketSize)

	// TS header
	packet[0] = tsSyncByte
	packet[1] = 0x40 | byte(pmtPID>>8) // payload_unit_start + PID high
	packet[2] = byte(pmtPID & 0xFF)
	packet[3] = 0x10 | (m.pmtContinuity & 0x0F)
	m.pmtContinuity++

	// Pointer field
	packet[4] = 0x00

	// PMT table
	pmt := packet[5:]
	pmt[0] = 0x02 // table_id = 2 (PMT)
	pmt[1] = 0xB0 // section_syntax_indicator=1
	pmt[2] = 18   // section_length
	pmt[3] = 0x00 // program_number high
	pmt[4] = 0x01 // program_number low
	pmt[5] = 0xC1 // version=0, current_next=1
	pmt[6] = 0x00 // section_number
	pmt[7] = 0x00 // last_section_number
	pmt[8] = 0xE0 | byte(audioPID>>8) // PCR PID high
	pmt[9] = byte(audioPID & 0xFF)    // PCR PID low
	pmt[10] = 0xF0 // reserved + program_info_length high
	pmt[11] = 0x00 // program_info_length low = 0

	// Stream entry: MP3 audio
	pmt[12] = 0x03                      // stream_type = 0x03 (MP3/MPEG-1 Audio)
	pmt[13] = 0xE0 | byte(audioPID>>8) // reserved + elementary PID high
	pmt[14] = byte(audioPID & 0xFF)
	pmt[15] = 0xF0 // reserved + ES_info_length high
	pmt[16] = 0x00 // ES_info_length low = 0

	// CRC32
	crc := crc32MPEG2(pmt[0:17])
	binary.BigEndian.PutUint32(pmt[17:21], crc)

	for i := 5 + 21; i < tsPacketSize; i++ {
		packet[i] = 0xFF
	}

	buf.Write(packet)
}

func (m *TSMuxer) writeAudioPES(buf *bytes.Buffer, data []byte, pts int64) {
	// Build PES header
	pesHeader := buildPESHeader(mp3StreamID, len(data), pts)
	payload := append(pesHeader, data...)

	offset := 0
	first := true
	for offset < len(payload) {
		packet := make([]byte, tsPacketSize)

		// TS header
		packet[0] = tsSyncByte
		pidHigh := byte(audioPID >> 8)
		if first {
			pidHigh |= 0x40 // payload_unit_start_indicator
			first = false
		}
		packet[1] = pidHigh
		packet[2] = byte(audioPID & 0xFF)

		remaining := len(payload) - offset
		payloadCapacity := tsPacketSize - 4 // 4 bytes TS header

		if remaining < payloadCapacity {
			// Need adaptation field for stuffing
			stuffingLen := payloadCapacity - remaining - 2 // 2 = adaptation_field_length + flags
			if stuffingLen < 0 {
				stuffingLen = 0
			}
			adaptLen := 1 + stuffingLen // flags + stuffing
			packet[3] = 0x30 | (m.audioContinuity & 0x0F) // adaptation + payload
			packet[4] = byte(adaptLen)
			packet[5] = 0x00 // adaptation flags (no PCR etc for simplicity)
			for i := 0; i < stuffingLen; i++ {
				packet[6+i] = 0xFF
			}
			copy(packet[4+1+adaptLen:], payload[offset:])
			offset = len(payload)
		} else {
			packet[3] = 0x10 | (m.audioContinuity & 0x0F) // payload only
			copy(packet[4:], payload[offset:offset+payloadCapacity])
			offset += payloadCapacity
		}

		m.audioContinuity++
		buf.Write(packet)
	}
}

// buildPESHeader creates a PES packet header with PTS.
func buildPESHeader(streamID byte, dataLen int, pts int64) []byte {
	var buf bytes.Buffer

	// PES start code: 00 00 01
	buf.Write([]byte{0x00, 0x00, 0x01})

	// Stream ID
	buf.WriteByte(streamID)

	// PES packet length (0 = unbounded, but for segments we set it)
	headerDataLen := 5 // PTS is 5 bytes
	pesLen := 3 + headerDataLen + dataLen // 3 = flags(2) + header_data_length(1)
	if pesLen > 0xFFFF {
		pesLen = 0 // unbounded for large segments
	}
	buf.WriteByte(byte(pesLen >> 8))
	buf.WriteByte(byte(pesLen & 0xFF))

	// Flags: marker bits, PTS present
	buf.WriteByte(0x80) // 10 marker, no scrambling, no priority, no alignment, no copyright, no original
	buf.WriteByte(0x80) // PTS only (no DTS)

	// PES header data length
	buf.WriteByte(byte(headerDataLen))

	// PTS (5 bytes)
	buf.Write(encodePTS(pts))

	return buf.Bytes()
}

// encodePTS encodes a 33-bit PTS value into the 5-byte MPEG-TS format.
func encodePTS(pts int64) []byte {
	p := make([]byte, 5)
	// Format: 0010 xxx1 | xxxxxxxx | xxxxxxx1 | xxxxxxxx | xxxxxxx1
	p[0] = 0x21 | byte((pts>>29)&0x0E)
	p[1] = byte(pts >> 22)
	p[2] = 0x01 | byte((pts>>14)&0xFE)
	p[3] = byte(pts >> 7)
	p[4] = 0x01 | byte((pts<<1)&0xFE)
	return p
}

// crc32MPEG2 calculates the CRC-32/MPEG-2 checksum used in MPEG-TS tables.
func crc32MPEG2(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
