package relay

// H.264 NALU (Network Abstraction Layer Unit) types
const (
	NALUTypeSlice  = 1  // Non-IDR slice
	NALUTypeDPA    = 2  // Data partition A
	NALUTypeIDR    = 5  // IDR (Instantaneous Decoder Refresh) — keyframe
	NALUTypeSEI    = 6  // Supplemental Enhancement Information
	NALUTypeSPS    = 7  // Sequence Parameter Set
	NALUTypePPS    = 8  // Picture Parameter Set
	NALUTypeAUD    = 9  // Access Unit Delimiter
	NALUTypeFiller = 12 // Filler data
)

// NALUnit represents a parsed H.264 NAL unit.
type NALUnit struct {
	Type   byte   // NALU type (lower 5 bits of first byte)
	RefIDC byte   // nal_ref_idc (bits 5-6 of first byte)
	Data   []byte // Raw NALU data including the type byte
}

// IsKeyframe returns true if this NALU is an IDR frame (keyframe).
func (n *NALUnit) IsKeyframe() bool {
	return n.Type == NALUTypeIDR
}

// IsSPS returns true if this is a Sequence Parameter Set.
func (n *NALUnit) IsSPS() bool {
	return n.Type == NALUTypeSPS
}

// IsPPS returns true if this is a Picture Parameter Set.
func (n *NALUnit) IsPPS() bool {
	return n.Type == NALUTypePPS
}

// ParseNALUs splits an Annex B byte stream into individual NAL units.
// Annex B format uses start codes: 00 00 00 01 or 00 00 01
func ParseNALUs(data []byte) []NALUnit {
	var units []NALUnit
	start := -1

	for i := 0; i < len(data); i++ {
		// Look for start code: 00 00 01 or 00 00 00 01
		isStartCode3 := i+2 < len(data) && data[i] == 0 && data[i+1] == 0 && data[i+2] == 1
		isStartCode4 := i+3 < len(data) && data[i] == 0 && data[i+1] == 0 && data[i+2] == 0 && data[i+3] == 1

		if isStartCode3 || isStartCode4 {
			// Save previous NALU
			if start >= 0 {
				naluData := data[start:i]
				if len(naluData) > 0 {
					units = append(units, NALUnit{
						Type:   naluData[0] & 0x1F,
						RefIDC: (naluData[0] >> 5) & 0x03,
						Data:   naluData,
					})
				}
			}

			if isStartCode4 {
				start = i + 4
				i += 3
			} else {
				start = i + 3
				i += 2
			}
		}
	}

	// Last NALU
	if start >= 0 && start < len(data) {
		naluData := data[start:]
		if len(naluData) > 0 {
			units = append(units, NALUnit{
				Type:   naluData[0] & 0x1F,
				RefIDC: (naluData[0] >> 5) & 0x03,
				Data:   naluData,
			})
		}
	}

	return units
}

// ContainsKeyframe returns true if the data contains an IDR NALU.
func ContainsKeyframe(data []byte) bool {
	units := ParseNALUs(data)
	for _, u := range units {
		if u.IsKeyframe() {
			return true
		}
	}
	return false
}

// ExtractSPSPPS extracts SPS and PPS NALUs from H.264 data.
// Returns (sps, pps) byte slices, or nil if not found.
func ExtractSPSPPS(data []byte) (sps []byte, pps []byte) {
	units := ParseNALUs(data)
	for _, u := range units {
		if u.IsSPS() && sps == nil {
			sps = make([]byte, len(u.Data))
			copy(sps, u.Data)
		}
		if u.IsPPS() && pps == nil {
			pps = make([]byte, len(u.Data))
			copy(pps, u.Data)
		}
	}
	return
}

// AVCCToAnnexB converts H.264 data from AVCC format (length-prefixed, used by RTMP/MP4)
// to Annex B format (start-code-prefixed, used by MPEG-TS).
// naluLengthSize is typically 4 (from the AVCDecoderConfigurationRecord).
func AVCCToAnnexB(data []byte, naluLengthSize int) []byte {
	var result []byte
	offset := 0

	for offset+naluLengthSize <= len(data) {
		// Read NALU length
		naluLen := 0
		for i := 0; i < naluLengthSize; i++ {
			naluLen = (naluLen << 8) | int(data[offset+i])
		}
		offset += naluLengthSize

		if naluLen <= 0 || offset+naluLen > len(data) {
			break
		}

		// Write Annex B start code + NALU data
		result = append(result, 0x00, 0x00, 0x00, 0x01)
		result = append(result, data[offset:offset+naluLen]...)
		offset += naluLen
	}

	return result
}
