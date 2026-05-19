package relay

import (
	"encoding/hex"
	"testing"
)

func TestIOSifyH264SPS_ProductionRTMPSource(t *testing.T) {
	// Real SPS from a production RTMP source whose encoder emits
	// fixed_frame_rate_flag=1 with no HRD params — a spec violation
	// per H.264 Annex E §E.2.1 that iOS Safari rejects with
	// kCMFormatDescriptionError_InvalidParameter on every sample.
	src, err := hex.DecodeString("67640028acd940780227e5c05a808080a0000003002000000791e30632c0")
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseH264SPS(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Sanity: structural fields preserve the source's stream shape.
	if info.ProfileIDC != 100 {
		t.Errorf("profile=%d want 100 (High)", info.ProfileIDC)
	}
	if info.LevelIDC != 40 {
		t.Errorf("level=%d want 40", info.LevelIDC)
	}
	// 1920 / 16 = 120 -> width_mb_minus1 = 119
	if info.PicWidthInMBsM1 != 119 {
		t.Errorf("pic_width_in_mbs_m1=%d want 119", info.PicWidthInMBsM1)
	}
	// 1088 / 16 = 68 -> height_in_map_units_minus1 = 67 (1080 + 8 crop)
	if info.PicHeightInMapUnitsM1 != 67 {
		t.Errorf("pic_height_in_map_units_m1=%d want 67", info.PicHeightInMapUnitsM1)
	}
	if info.FrameCropBottomOffset != 4 {
		t.Errorf("frame_crop_bottom_offset=%d want 4", info.FrameCropBottomOffset)
	}
	if !info.FrameMBsOnlyFlag {
		t.Errorf("frame_mbs_only_flag should be true")
	}

	// Rewrite must produce a non-empty byte string of NAL type 7.
	rewritten := IOSifyH264SPS(src, 30)
	if len(rewritten) < 4 {
		t.Fatalf("rewritten too short: %d bytes", len(rewritten))
	}
	if rewritten[0]&0x1F != 7 {
		t.Errorf("rewritten NAL type=%d want 7", rewritten[0]&0x1F)
	}

	// Parse the rewritten SPS — should round-trip with same structural
	// dimensions. The VUI is intentionally different (we overwrite it).
	info2, err := ParseH264SPS(rewritten)
	if err != nil {
		t.Fatalf("rewritten parse: %v", err)
	}
	if info2.ProfileIDC != info.ProfileIDC ||
		info2.LevelIDC != info.LevelIDC ||
		info2.PicWidthInMBsM1 != info.PicWidthInMBsM1 ||
		info2.PicHeightInMapUnitsM1 != info.PicHeightInMapUnitsM1 ||
		info2.FrameCropBottomOffset != info.FrameCropBottomOffset ||
		info2.MaxNumRefFrames != info.MaxNumRefFrames ||
		info2.ChromaFormatIDC != info.ChromaFormatIDC {
		t.Errorf("structural fields changed across rewrite: %+v vs %+v", info, info2)
	}
}

func TestIOSifyH264SPS_UnparseableLeftAlone(t *testing.T) {
	// Garbage bytes should NOT panic and should pass through unchanged.
	garbage := []byte{0x67, 0xff, 0xff, 0xff, 0xff}
	out := IOSifyH264SPS(garbage, 30)
	if string(out) != string(garbage) {
		t.Errorf("garbage should pass through unchanged")
	}
}

func TestRewriteInlineSPS_ReplacesInlineSPS(t *testing.T) {
	src, _ := hex.DecodeString("67640028acd940780227e5c05a808080a0000003002000000791e30632c0")
	// Build: start_code + SPS + start_code + dummy_PPS + start_code + dummy_IDR
	annexB := []byte{0x00, 0x00, 0x00, 0x01}
	annexB = append(annexB, src...)
	annexB = append(annexB, 0x00, 0x00, 0x00, 0x01, 0x68, 0xee, 0x3c, 0xb0) // PPS
	annexB = append(annexB, 0x00, 0x00, 0x00, 0x01, 0x65, 0xb8, 0x20, 0x01) // IDR (truncated)

	out := rewriteInlineSPS(annexB, 30)
	if len(out) <= 4 {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	// The rewritten output must NOT contain the original (invalid) SPS.
	if containsBytes(out, src) {
		t.Errorf("original (invalid) SPS still present in output")
	}
	// Should still contain the dummy PPS NALU header byte 0x68.
	if !containsBytes(out, []byte{0x00, 0x00, 0x00, 0x01, 0x68}) {
		t.Errorf("PPS start code lost during rewrite")
	}
	// Should still contain the IDR NALU header byte 0x65.
	if !containsBytes(out, []byte{0x00, 0x00, 0x00, 0x01, 0x65}) {
		t.Errorf("IDR start code lost during rewrite")
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
