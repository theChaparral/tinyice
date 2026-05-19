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

// HasInlineParameterSets returns true if the Annex-B byte stream
// already contains an SPS (NALU type 7) or PPS (NALU type 8). Used
// by ingest paths to decide whether to additionally prepend the
// cached parameter sets to a keyframe — some encoders (OBS / ffmpeg
// with -bsf:v dump_extra) already inline SPS+PPS at every IDR, and
// adding a second copy makes iOS Safari's hardware H.264 decoder
// silently freeze on the first frame ("audio plays, video blank").
func HasInlineParameterSets(data []byte) bool {
	for _, u := range ParseNALUs(data) {
		if u.Type == 7 || u.Type == 8 {
			return true
		}
	}
	return false
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

// ParseSPSResolution returns the picture width/height (in luma pixels)
// encoded in an H.264 SPS NALU. sps may be either the raw RBSP (no
// start code, with the 0x67 header byte included) or just the payload
// starting at seq_parameter_set_id; we strip the header if present.
// Returns (0, 0, false) if the SPS can't be parsed — common enough
// that callers should treat unknown resolutions as informational.
func ParseSPSResolution(sps []byte) (width, height int, ok bool) {
	if len(sps) < 4 {
		return 0, 0, false
	}
	// Skip NALU header byte if this looks like a full NALU.
	if sps[0]&0x1F == NALUTypeSPS {
		sps = sps[1:]
	}
	// Strip emulation prevention bytes: 0x00 0x00 0x03 -> 0x00 0x00.
	rbsp := make([]byte, 0, len(sps))
	for i := 0; i < len(sps); i++ {
		if i+2 < len(sps) && sps[i] == 0 && sps[i+1] == 0 && sps[i+2] == 0x03 {
			rbsp = append(rbsp, 0, 0)
			i += 2
			continue
		}
		rbsp = append(rbsp, sps[i])
	}
	if len(rbsp) < 3 {
		return 0, 0, false
	}
	defer func() {
		// Guard against short-SPS reads in the bit reader.
		if r := recover(); r != nil {
			width, height, ok = 0, 0, false
		}
	}()

	br := &h264BitReader{data: rbsp}
	profileIDC := br.u(8)
	_ = br.u(8) // constraint flags + reserved
	_ = br.u(8) // level_idc
	br.ue()     // seq_parameter_set_id

	chromaFormat := 1
	separateColourPlane := false
	switch profileIDC {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		chromaFormat = br.ue()
		if chromaFormat == 3 {
			separateColourPlane = br.u(1) == 1
		}
		br.ue()     // bit_depth_luma_minus8
		br.ue()     // bit_depth_chroma_minus8
		_ = br.u(1) // qpprime_y_zero_transform_bypass_flag
		if br.u(1) == 1 {
			// seq_scaling_matrix_present_flag — skip lists.
			count := 8
			if chromaFormat == 3 {
				count = 12
			}
			for i := 0; i < count; i++ {
				if br.u(1) == 1 {
					size := 16
					if i >= 6 {
						size = 64
					}
					lastScale, nextScale := 8, 8
					for j := 0; j < size; j++ {
						if nextScale != 0 {
							delta := br.se()
							nextScale = (lastScale + delta + 256) % 256
						}
						if nextScale != 0 {
							lastScale = nextScale
						}
					}
				}
			}
		}
	}
	br.ue() // log2_max_frame_num_minus4
	picOrderCntType := br.ue()
	if picOrderCntType == 0 {
		br.ue() // log2_max_pic_order_cnt_lsb_minus4
	} else if picOrderCntType == 1 {
		_ = br.u(1) // delta_pic_order_always_zero_flag
		br.se()     // offset_for_non_ref_pic
		br.se()     // offset_for_top_to_bottom_field
		n := br.ue()
		for i := 0; i < n; i++ {
			br.se()
		}
	}
	br.ue()     // max_num_ref_frames
	_ = br.u(1) // gaps_in_frame_num_value_allowed_flag

	picWidthMBsMinus1 := br.ue()
	picHeightMapUnitsMinus1 := br.ue()
	frameMBsOnly := br.u(1) == 1
	if !frameMBsOnly {
		_ = br.u(1) // mb_adaptive_frame_field_flag
	}
	_ = br.u(1) // direct_8x8_inference_flag

	cropLeft, cropRight, cropTop, cropBottom := 0, 0, 0, 0
	if br.u(1) == 1 {
		cropLeft = br.ue()
		cropRight = br.ue()
		cropTop = br.ue()
		cropBottom = br.ue()
	}

	rawWidth := (picWidthMBsMinus1 + 1) * 16
	rawHeight := 16 * (picHeightMapUnitsMinus1 + 1)
	if !frameMBsOnly {
		rawHeight *= 2
	}

	subWidthC, subHeightC := 1, 1
	if !separateColourPlane {
		switch chromaFormat {
		case 1:
			subWidthC, subHeightC = 2, 2
		case 2:
			subWidthC, subHeightC = 2, 1
		}
	}
	frameMBsMultiplier := 1
	if !frameMBsOnly {
		frameMBsMultiplier = 2
	}

	width = rawWidth - subWidthC*(cropLeft+cropRight)
	height = rawHeight - subHeightC*frameMBsMultiplier*(cropTop+cropBottom)
	if width <= 0 || height <= 0 || width > 16384 || height > 16384 {
		return 0, 0, false
	}
	return width, height, true
}

// h264BitReader is a minimal MSB-first bit reader that supports the
// fixed and Exp-Golomb codes used by the SPS syntax.
type h264BitReader struct {
	data []byte
	bit  int // bit index from MSB of data[0]
}

func (b *h264BitReader) u(n int) int {
	v := 0
	for i := 0; i < n; i++ {
		byteIdx := b.bit / 8
		if byteIdx >= len(b.data) {
			panic("h264: short SPS")
		}
		shift := 7 - (b.bit % 8)
		v = (v << 1) | int((b.data[byteIdx]>>shift)&1)
		b.bit++
	}
	return v
}

func (b *h264BitReader) ue() int {
	zeros := 0
	for b.u(1) == 0 {
		zeros++
		if zeros > 32 {
			panic("h264: ue overflow")
		}
	}
	if zeros == 0 {
		return 0
	}
	suffix := b.u(zeros)
	return (1 << zeros) - 1 + suffix
}

func (b *h264BitReader) se() int {
	v := b.ue()
	if v&1 == 1 {
		return (v + 1) / 2
	}
	return -(v / 2)
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
