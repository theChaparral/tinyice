# How I Built TinyIce: A Modern, Lightweight Icecast Server in Go (with a little help from AI)

**By [syso42](https://medium.com/@syso42)**

Streaming audio shouldn't be hard. Yet, for years, setting up a robust, secure, and performant Icecast server often meant wrestling with complex XML configurations, outdated dependencies, and resource-heavy setups. 

Enter **TinyIce ❄️**: a lightweight, self-contained, and multi-tenant Icecast2-compatible server written in Go. But the story isn't just about the server itself—it’s about the unique "Human-in-the-Loop" development process I used to bring it to life.

---

## The Vision: Streaming Without the Friction

The goal for TinyIce was simple: **Instant Deployment.** I wanted a single binary that could:
1.  Handle standard Icecast protocols (supporting BUTT, OBS, VLC).
2.  Provide multi-tenant admin dashboards (so users can manage their own mount points).
3.  Offer real-time observability without heavy external dependencies.
4.  Be secure by default (auto-HTTPS via ACME, bcrypt password hashing).

Go was the obvious choice for this. Its concurrency model (goroutines and channels) is practically built for streaming data, and its ability to produce a static binary with embedded assets meant I could deliver on the promise of "Zero-Config."

---

## The Catalyst: Utilising Free LLMs

In today’s landscape, innovation moves fast. To build TinyIce, I leveraged free Large Language Models (LLMs) as a high-speed "scaffolding agent." 

AI was instrumental in:
*   **Rapid Prototyping**: Generating the boilerplate for the Icecast protocol headers and the initial CSS for the dashboard.
*   **Contextual Refactoring**: Assisting in decomposing large functions into smaller, more maintainable Go idiomatic structures.
*   **UI/UX Exploration**: Iterating through different design aesthetics—from standard grids to the current "Glassmorphism" look—in minutes rather than hours.

By using AI, I was able to bypass the "blank page" syndrome and focus immediately on the architectural nuances that make a server truly performant.

---

## The "Human-in-the-Loop": Why Manual Review Still Wins

While the AI provided the bricks, the architecture required a human hand. AI can write a loop, but it doesn't always understand the high-concurrency pitfalls of binary stream broadcasting.

My process followed a strict cycle:
1.  **AI Scaffolding**: Generate initial logic for a feature.
2.  **Manual Code Review**: Rigorously audit the AI's output for security flaws (like CSRF or race conditions).
3.  **Architectural Refinement**: Implementing low-level Go features like `http.Hijacker` to take manual control of TCP connections—something AI often glosses over.
4.  **Performance Tuning**: Optimizing memory usage per listener (now down to ~400KB) and ensuring thread-safe data transfer using Go's `sync/atomic` and `RWMutex`.

The result? A codebase that is clean, highly efficient, and human-verified for production readiness.

---

## Technical Highlights

*   **Pub/Sub Engine**: TinyIce uses Go channels to broadcast data. Every listener gets a dedicated channel, ensuring that one slow connection doesn't "clog" the server for others.
*   **SSE Dashboards**: Instead of heavy polling, we use **Server-Sent Events** to push metrics every 500ms. It feels like a native app.
*   **Pure-Go SQLite**: We use a CGO-free SQLite driver for the playback history. This keeps the project 100% portable and cross-compilable.
*   **Custom ACME Support**: Built for everyone from enterprise users to homelab enthusiasts running their own private CAs.

---

## What’s Next?

TinyIce is currently at **v0.2.9**, and we’ve already implemented persistent song history, approval-based workflows, and full playlist support (`.m3u8`, `.pls`). 

The journey has shown me that the future of software engineering isn't AI *replacing* developers—it's developers *orchestrating* AI to reach the goal faster, while keeping their hands firmly on the wheel of code quality and security.

**Check out the project on GitHub:** [DatanoiseTV/tinyice](https://github.com/DatanoiseTV/tinyice)

*If you enjoyed this deep dive, follow me here on Medium [syso42](https://medium.com/@syso42) for more on Go, streaming tech, and AI-assisted development!*
