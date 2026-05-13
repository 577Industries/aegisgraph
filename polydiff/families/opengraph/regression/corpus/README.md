# PolyDiff opengraph-family regression corpus

This directory holds **hash-pin files only** for opengraph-family
anchored witnesses. Per Asemarefactor.md §"Engine 1: PolyDiff Extended"
and the schema additive-only policy (ADR-0010), witness BYTES never
appear in this repository.

## Layout

| File | What it pins |
|---|---|
| `anchor_fb_crawler_2018_relative_url.html.sha256` | Facebook's OG crawler resolved relative URLs (e.g. `./landing`) against the crawled page's URL one way; downstream WHATWG-URL-conformant consumers resolved them another way (~2018). The divergence allowed phishing-tracker bypasses — Facebook's preview surfaced one URL while the actual click navigated elsewhere. Exercises the **og_url divergence -> MEDIUM-HIGH** triage rule. |
| `anchor_twitter_card_player_xss.html.sha256` | `twitter:player` URL fields had inconsistent sanitization between Twitter's crawler and downstream embedders. One impl emitted a player card with un-sanitized URL; the other rejected the card entirely. Exercises the **twitter_card_type divergence -> MEDIUM** triage rule and the historical XSS-prone link-preview class. |
| `anchor_oembed_provider_origin_confusion.json.sha256` | When an OG page declares one canonical URL but the matching oEmbed provider response declares a different one, downstream consumers inconsistently picked one or the other. The attacker controlled whichever they trusted. Exercises the **canonical_url divergence -> MEDIUM** (link-preview-confusion class, Snyk-2022 URL-confusion extended to embed metadata). |
| `anchor_synthetic_meta_tag_quote_escape.html.sha256` | Synthetic anchor of our design: `<meta name='og:title' content='he said "hi"'>` uses nested quote chars; one impl crashes the underlying HTML tokenizer while another truncates the title at the inner quote. Exercises the **decode_outcome divergence (crash + ok) -> HIGH** triage rule. |

The canonical manifest with sizes, expected fact-vector diffs, and triage
expectations is `../corpus.json`. The rediscovery manifest with SHA pins
(Asemarefactor.md lines 35-37 contract) is `../INDEX.json`.

## Witness bytes provenance

The historical-bug witnesses are vendored privately at
`reprochain/corpora-private/og_*.html`. That directory is
engineering-side only and excluded from every public release through
`validator/sanitize_check.py` Rule 5 + the existing `EXCLUSIONS.md`
allowlist.

The opengraph family **never reads bytes** from the corpus in the
public/engineering pipeline. The diff engine operates on
`(witness_sha256, witness_size_bytes)` and per-implementation fact
vectors only.

## Public citation guidance

The Facebook crawler relative-URL quirk has multiple public write-ups
from researchers who reported phishing-preview bypasses; specific
references are kept engineering-private to avoid amplifying any
still-exploitable variants. The Twitter Card `player` XSS class is
documented in academic surveys of link-preview vulnerabilities. The
oEmbed origin-confusion class generalizes the Snyk-2022 URL-confusion
research findings to embed metadata. The meta-tag quote-escape
divergence is a synthetic case of our own design that exercises the
canonical decode_outcome triage rule.

## Network constraint

Opengraph-family wrappers MUST NOT fetch URLs over the network. The
HTML / JSON witness bytes are supplied to each wrapper subprocess on
stdin; nothing in this directory or in the wrapper code is permitted to
make outbound HTTP requests. This invariant is checked by the wrapper
subprocess contract tests.
