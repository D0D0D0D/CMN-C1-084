# CMN-C1-084 — AI Agent Lifecycle & Governance Policy Q&A Agent

> **Category**: Cat 1 (single technical capability)
> **Industry**: CMN

## Overview

This template answers questions about AI-agent lifecycle and governance — deployment approval,
access, risk, data handling, compliance — from an operator-curated allowlist of web sources. It
classifies the question into a governance topic, fetches the sources configured for that topic
over HTTPS, and returns an answer that carries every source URL and its retrieval timestamp.

The design point is that nothing in the answer is allowed to be uncited. The response is composed
strictly from the text that was actually fetched, and an output gate re-verifies each citation
before the answer leaves the agent:

- **Sources are an allowlist, not a search.** Only hosts listed in `source_allowlist` are
  fetchable. The fetch layer resolves the host and rejects private, loopback, link-local and
  reserved addresses, so a redirect or a DNS answer cannot pull the agent onto an internal
  network.
- **Citations are re-verified after the answer is written.** Every URL in the draft must be a URL
  that was actually fetched in this invocation *and* must belong to a host on the configured
  allowlist. A citation that fails either test blocks the response rather than being stripped
  from it.
- **An unreachable source is not silently answered around.** When no configured source can be
  fetched, the agent returns an explicit "no current information" answer instead of composing one
  from prior knowledge. That path is the only one exempt from the citation requirement, and the
  exemption is driven by a structured state flag set by the fetch step — never by a marker string
  inside the generated text, which a prompt injection could forge.
- **A transient fetch failure retries, bounded.** Retries stop at `max_retry`; the final attempt
  falls back rather than ending on a retry status.

The agent does not provide legal or regulatory advice, does not approve a deployment, and does not
decide policy. It reports what its configured sources currently say, with the receipts.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Integration

Provide:

- an AgentCore runtime;
- your own `source_allowlist` in `config/config.yaml` — the shipped list is a public-source
  example (financial-regulator, standards-body and ministry pages), not a recommendation;
- caller authentication in front of the entry adapter.

An LLM is **optional**. The shipped build declares `generation_mode: deterministic` and never
calls a model: `ContextGroundedLLMClient` composes the answer from the fetched excerpts and the
`Sources:` block. `MainNode` accepts an injected `llm_client` implementing the module's `generate`
protocol, which is where a model goes when a fork wants one — the citation gate downstream is
unchanged either way, and it is what keeps a model from inventing a source.

`config/config.yaml` holds the runtime parameters. Be aware of which ones the shipped code
actually consumes — a fork that changes the others needs to wire them first:

| Key | Meaning |
|---|---|
| `source_allowlist` | **Read on every invocation.** The fetchable sources; each entry is `{url, title, topics}`, where `topics` selects the entry for a classified question and `all` selects it for every question |
| `max_retry` (`3`) | Declared for the framework's config validation. The fetch retry ceiling is a constant of the same value inside the main node, not read from here |
| `timeout_seconds` (`30`) | Declared; not consumed by this template's code |
| `fetch.cache_ttl_seconds` (`600`), `fetch.per_host_min_interval_s` (`1.0`) | Declared. The fetch service takes these as constructor arguments, and the main node builds it without passing them, so the effective values are the service defaults: a 600-second cache and no enforced spacing between requests to one host |

The template does not crawl, does not search the open web, does not maintain a vector store or a
knowledge base, and does not render JavaScript — a source that serves its content only to a
scripted browser will contribute a challenge page rather than policy text, so allowlist entries
should point at pages that are readable as plain HTML.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent is built to be served by the platform. Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Supplied by the platform's own package registry at build time. It is not published on public PyPI, so `pip install -e .` alone does not fetch it. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

There is no degraded mode and no bundled framework. `pyproject.toml` declares no runtime
dependencies, so `pip install -e .` installs the template's own code and nothing else: without
the AgentCore wheel from the platform registry, importing the agent fails at
`from framework.graph.agent_base_graph import AgentBaseGraph` — start-up stops there rather than
running in a partially wired state.

With the framework present, the standalone server in `src/api/server.py` does start without the
rest of the platform: it compiles the graph, provisions secrets from the local provider, and
serves `/health`. What it will not do is let an unauthenticated caller in — see *Input*. The test
suite runs with no platform connection and no network.

## Input

`POST /invoke` takes a JSON body with `input` and an optional `session_id`. There is no
`input_context` field on this entry point; the invocation channel is set by the adapter.

Callers must be authenticated. The entry adapter uses a verified trust level stamped by upstream
middleware when one is present; otherwise, when `INVOKE_AUTH_TOKEN` is set on the server
environment, a matching `Authorization: Bearer` header promotes the caller from `ANONYMOUS` to
`VERIFIED_EXTERNAL`. A caller that is neither middleware-verified nor token-authenticated is
rejected with **401** — including one that middleware explicitly stamped as anonymous. Every node
requires `VERIFIED_EXTERNAL`, so there is no anonymous path into the graph.

```bash
curl -X POST http://127.0.0.1:8000/invoke \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${INVOKE_AUTH_TOKEN}" \
  -d '{
    "input": "What approval is required to deploy an autonomous agent to production?",
    "session_id": "example-session"
  }'
```

Input fails closed: an empty query and one over 4000 characters are both rejected by the input
gate, and email addresses, phone numbers and identifier-shaped digit runs are masked before the
query is classified, logged or sent to a model.

## Output

The standard AgentCore envelope is returned: `output`, `status`, `trace_id`, `correlation_id` and
`node_history`. `output` is the cited answer with the risk label of the queried activity appended:

```
Based on the current governance sources, here is guidance for: <the question>

- <excerpt from a fetched source>

Risk level of this activity: high.

Sources:
[1] https://www.example.org/policy (fetched_at=2026-07-17T00:00:00+00:00)

[risk_label: high]
```

When no configured source could be fetched, `output` is the explicit no-information answer
carrying a `no_sources_available` marker, and `status` is still `success` — an honest "I could not
check" is a result, not an error. A citation-integrity failure is different: it ends as
`status=error` with the reason in the audit trail, and no answer text is returned.

The audit event emitted for each answer records the topic, the risk label, the cited source URLs,
their fetch timestamps and whether the fallback fired — not the question text and not the answer.

Values above are illustrative; real output depends on the configured sources and what they say
when they are fetched.

## Security and Limitations

Every node requires verified-external trust, so an unauthenticated caller is stopped before any
node body runs. The input gate bounds and masks the query. The output gate blocks a credential
literal in the answer, masks personal information, and enforces citation integrity as described
above — the allowlist is re-checked from configuration at that point, so even if the fetch layer
were bypassed, an off-allowlist host could not be cited.

Known limits worth stating plainly:

- **A citation proves retrieval, not correctness.** The agent shows what a source said and when it
  was fetched. It does not evaluate whether the source is authoritative for your organisation, and
  it does not reconcile two sources that disagree.
- **The answer is only as current as the fetch.** A cached page is reused for
  `fetch.cache_ttl_seconds`, and a page that changed after retrieval is not re-checked.
- **Topic classification is keyword-based**, and falls back to `compliance` when a question
  matches no keyword — so an off-domain question is answered from the compliance sources rather
  than refused. Give an entry the `all` topic if it should back every question.
- **Extraction is plain-text.** A page behind a script challenge, a login, or a PDF yields no
  usable policy text.

Output is machine-generated and assistive. It does not substitute for expert review, and any
decision that matters should be made against the primary source by a person.

## Release

- Version: 1.0.0
- Category: single technical capability (Cat 1), fixed five-node backbone
- Generation mode: `deterministic` — the shipped build never calls a model
- HITL: not enabled
- Persistence: none — no checkpointer is configured
- Secrets: none required
- External API clients: none bundled; outbound HTTPS is limited to the configured allowlist

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection and without network access — the fetch layer is injected
in tests. Running the agent itself does reach the network: `MainNode` fetches the configured
allowlist over HTTPS on every invocation, so point `source_allowlist` at sources you intend to be
contacted before serving traffic.

## Documentation

`docs/02_design.md` carries the node flow, the state schema, the fetch and SSRF controls and the
security design. `docs/03_test_spec.md` records the test specification and the verification
results.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and test specifications
```

See `docs/02_design.md` for the design and `docs/03_test_spec.md` for the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
