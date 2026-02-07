🏗️ Architecture — Secure Agentic Browser
Overview

Secure Agentic Browser is a security framework that protects AI-powered browser agents from malicious web content such as prompt injection, phishing, and UI deception.

Instead of relying on a user interface, the system operates as a runtime security layer that analyzes pages before an AI agent can interact with them.

The architecture follows a multi-layer, defense-in-depth model, inspired by real-world security systems (WAFs, EDRs, Zero Trust).

High-Level Flow
┌──────────────┐
│ AI Agent     │
│ (agent.py)   │
└──────┬───────┘
       │
       ▼
┌─────────────────────────┐
│ Security Mediator       │
│ (security_mediator.py) │
└──────┬──────────────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│ Multi-Layer Security Analysis             │
│                                          │
│ 1. DOM Structure Analysis                 │
│ 2. NLP Content Classification             │
│ 3. LLM Intent Reasoning (Gemini)           │
│ 4. Risk Aggregation & Policy Enforcement  │
└──────┬───────────────────────────────────┘
       │
       ▼
┌────────────────────┐
│ Decision Engine    │
│ ALLOW / WARN /     │
│ CONFIRM / BLOCK    │
└────────────────────┘

Core Components
1️⃣ Agent Layer (src/core/agent.py)

The AgenticBrowser is an AI-controlled browser agent powered by Playwright.

Responsibilities:

Navigate to web pages

Extract page content

Request security analysis before any action

Execute actions only if permitted

Key Design Choice:

The agent never directly trusts page content — every action passes through the security mediator.

2️⃣ Security Mediator (src/core/security_mediator.py)

The SecurityMediator orchestrates all security checks and ensures low latency by selectively invoking expensive analysis layers.

Responsibilities:

Coordinate all analyzers

Decide when to invoke LLM reasoning

Aggregate signals into a unified risk report

Enforce security decisions

This component acts as the central policy enforcement point.

Analysis Layers
🧩 Layer 1 — DOM Analysis

File: src/analyzers/dom_analyzer.py

A fast, rule-based analysis of the page’s HTML structure.

Detects:

Hidden elements (CSS tricks, off-screen text)

Suspicious forms (external credential submission)

Malicious iframes

Risky JavaScript patterns

Why it matters:
Most prompt injection and phishing attacks rely on DOM manipulation rather than visible text.

🧠 Layer 2 — NLP Classification

File: src/analyzers/nlp_classifier.py

Lightweight text analysis over visible and hidden content.

Detects:

Instruction override attempts

Social engineering language

Credential harvesting cues

Optimized for:
High recall with minimal performance impact.

🤖 Layer 3 — LLM Intent Reasoning (Gemini)

File: src/analyzers/llm_reasoner.py

Used only for borderline cases where static analysis is insufficient.

Capabilities:

Understand attacker intent

Detect sophisticated prompt injection

Validate agent actions against page context

Cost-Controlled Design:

Triggered only above a configurable risk threshold

Deterministic temperature for security use

Risk & Policy Layer
⚖️ Multi-Factor Risk Calculator

File: src/policies/risk_calculator.py

Aggregates signals from all layers into a normalized risk score (0.0–1.0).

Factors considered:

DOM threat indicators

NLP confidence

LLM intent analysis

Behavioral signals (extensible)

Actions:

Risk Score	Action
≥ 0.80	BLOCK
≥ 0.50	CONFIRM
≥ 0.30	WARN
< 0.30	ALLOW
Utilities & Observability
🧪 Metrics Collection

File: src/utils/metrics_collector.py
Tracks precision, recall, and evaluation statistics.

⏱️ Performance Monitoring

File: src/utils/performance_monitor.py
Ensures security checks meet latency targets.

🧾 Explanation Generator

File: src/utils/explanation_generator.py
Produces human-readable explanations for decisions — critical for trust and debugging.

Design Principles

Zero Trust: No page content is trusted by default

Defense in Depth: Multiple independent detection layers

Fail-Safe Defaults: Unsafe behavior is blocked by default

Explainability: Every decision is traceable and explainable

No UI Dependency: Designed for headless and automated agents

Why No UI?

This project is intentionally UI-agnostic.

Security systems in production environments:

Run headlessly

Operate via logs and policies

Protect autonomous systems, not humans

The terminal output serves as the security dashboard.

Extensibility

Future extensions can include:

Runtime behavioral monitoring

Browser fingerprint anomaly detection

Enterprise policy integration

Agent-to-agent trust negotiation

Summary

Secure Agentic Browser provides a robust security layer for autonomous web agents, combining static analysis, machine learning, and LLM-based reasoning into a single, enforceable decision engine.

It is designed to be practical, extensible, and production-aligned.