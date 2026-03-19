# Phase 2: Pipeline Abstraction Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a protocol-agnostic pipeline architecture that wraps existing streaming code, enabling future protocols (HLS, RTMP, SRT) to plug in as adapters without touching core buffer/broadcast logic.

**Architecture:** New abstraction layer on top of existing `relay/` code. The existing `Relay`, `Stream`, `Streamer`, `WebRTCManager`, and `RelayManager` continue to work unchanged. The pipeline layer wraps them with new interfaces. No existing code is modified — only new files are created and `interfaces.go` is extended.

**Tech Stack:** Go 1.25, existing relay package.

**Spec:** `docs/superpowers/specs/2026-03-14-streaming-hardening-design.md` (Phase 2)

---

## Task 1: Create core pipeline types and interfaces

**Files:**
- Create: `relay/pipeline.go`
- Create: `relay/pipeline_test.go`

Create the foundational types: `MediaType`, `Track`, `TrackMetadata`, `SourceHealth`, `PipelineHealth`, `IngestSource`, `OutputAdapter`, `HTTPOutputAdapter`, `PeerOutputAdapter`, `Pipeline`.

Key design: `Track` wraps existing `*Stream` to reuse buffer/listener infrastructure.

---

## Task 2: Create PipelineManager wrapping Relay

**Files:**
- Create: `relay/pipeline_manager.go`
- Create: `relay/pipeline_manager_test.go`

`PipelineManager` wraps `*Relay` and manages `Pipeline` instances. Provides backward-compatible `GetOrCreateStream(mount)` that internally creates a single-track audio pipeline. Manages pipeline lifecycle.

---

## Task 3: Create ingest adapters

**Files:**
- Create: `relay/ingest_icecast.go`
- Create: `relay/ingest_webrtc.go`
- Create: `relay/ingest_autodj.go`
- Create: `relay/ingest_relay.go`

Thin wrappers implementing `IngestSource` that delegate to existing managers. These don't change any behavior — they provide the new interface for existing source types.

---

## Task 4: Create output adapters

**Files:**
- Create: `relay/output_icecast.go`
- Create: `relay/output_webrtc.go`

Thin wrappers implementing `OutputAdapter`/`HTTPOutputAdapter`/`PeerOutputAdapter` that delegate to existing streaming logic.

---

## Task 5: Integration test and commit

- Build: `go build ./...`
- Test: `go test ./relay/ -v -race`
- Commit all Phase 2 files together
