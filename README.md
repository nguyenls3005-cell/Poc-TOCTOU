<div align="center">

# Sandbox TOCTOU

### `sandbox_extension` TOCTOU — iOS Sandbox Escape PoC

[![Build IPA](https://github.com/speedyfriend433/sandbox_extension-TOCTOU-bug/actions/workflows/build.yml/badge.svg)](https://github.com/speedyfriend433/sandbox_extension-TOCTOU-bug/actions/workflows/build.yml)
[![Platform](https://img.shields.io/badge/platform-iOS%2015.0%2B-blueviolet)](https://www.apple.com/ios)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-unpatched-red)]()
[![Signed](https://img.shields.io/badge/status-unsigned-orange)]()

*Deterministic TOCTOU against Apple's `sandbox_extension_consume()` — no race timing required.*

</div>

---

## Overview

This project is a **GUI wrapper** around the original PoC in [`poc.m`](./poc.m). It demonstrates a **Time-of-Check to Time-of-Use** flaw in iOS's `sandbox_extension` API that allows an app to escape its container and read arbitrary files outside its sandbox — including system files like `/etc/passwd` and preference plists belonging to other processes.

- **Deterministic** — no probabilistic win rate, no thread racing, no retry loops.
- **Unsigned IPA** — builds in GitHub Actions on every push.
- **Status** — *Not patched. Apple does not treat this as a security issue.*

---

## The Bug

### Root cause

`sandbox_extension_issue_file()` issues a **capability token bound to a path**, not an inode. The kernel validates that the app can access the resolved path at issuance time, but `sandbox_extension_consume()` **re-resolves the token's path** at consumption time — trusting whatever the symlink points to *now*.
