# テスト仕様書 — CMN-C1-084

AI Agent Lifecycle & Governance Policy Q&A Agent（Live Web Fetch + LLM コンテキスト注入, Cat 1）。

## テスト戦略

- カバレッジ目標: src/ 全体で 80% 以上（現状 86%。コア（nodes / web_fetch_service / service / security）は 89〜100%）。
- テスト種別: Unit（`tests/unit/`）/ Integration（`tests/integration/`）/ Proof-of-Boundary（`tests/proof_of_boundary/`）。
- **実ネットワークアクセスは一切行わない**。WebFetchService の transport（`fetcher`）と DNS resolver（`resolver`）は注入シームになっており、テストはスタブを注入して SSRF 判定ロジックをオフラインで単体検証する。
- LLM も `src/services/llm_client.py` の注入シーム経由。デフォルト実装は取得済みコンテキストのみから引用付き回答を組み立てるオフライン安全実装。

## Framework Compliance Tests（必須）

| TC-ID | テスト | 期待結果 | 実装 / 結果 |
|-------|------|----------|------|
| TC-01 | State 契約: flat TypedDict（Pydantic/dataclass なし） | 型チェック PASS、AgentState 継承 | `proof_of_boundary/test_state_safety.py` ✅ |
| TC-02 | 不正入力で拒否（S-2 入力ゲート） | 空/過大入力で status=error | `unit/test_pre_process_node.py::test_empty_input_rejected_s2 / test_oversized_input_rejected_s2` ✅ |
| TC-03 | State に JWT/credential を入れない | credential フィールド名・型なし | `test_state_safety.py::test_state_file_safety` ✅ |
| TC-04 | InvocationContext は State に入れない | State 注釈に InvocationContext なし | `test_state_safety.py::test_invocation_context_not_in_state` ✅ |
| TC-05 | `emit_trace_event`（S-4）が呼ばれる | 応答ごとに監査イベント emit | `unit/test_post_process_node.py::test_emit_trace_event_called_on_success` ✅ |
| TC-06 | S-2 入力ゲート非バイパス | PII スクラブ・bounds が必ず実行 | `unit/test_pre_process_node.py::test_pii_scrubbed_before_processing` ✅ |
| TC-07 | S-3 出力ゲート非バイパス | 引用整合・credential/PII を必ず検査 | `unit/test_post_process_node.py`（TestS3CitationGate 一式）✅ |
| TC-08 | `required_trust_level` declared and enforced — dedicated S-1 boundary coverage MUST call `node(state)` (via `__call__`) for every privileged node, or use equivalent parameterized coverage | Insufficient trust level → execution refused *before* `execute()`; test must prove `execute()` was not called. Direct `node.execute(state)` is permitted only for isolated business-logic unit tests: it does not satisfy TC-08, but is not a finding when TC-08 and PB-6 coverage pass. | `integration/test_main_node_integration.py::TestS1TrustGate::test_anonymous_caller_denied` ✅ |

## ドメイン / SSRF テスト（本テンプレートの核）

| TC-ID | テスト | 期待結果 | 実装（`tests/unit/test_web_fetch_ssrf.py` ほか） |
|-------|------|----------|------|
| TC-10 | allowlist 内 host のみ取得 | allowlist 外 host は SecurityViolationError | `TestAllowlist` ✅ |
| TC-11 | http/https 以外のスキーム拒否 | file/gopher/ftp で例外 | `TestScheme` ✅ |
| TC-12 | メタデータ host 拒否 | 169.254.169.254 / metadata.google.internal で例外 | `TestMetadataAndPrivateIP` ✅ |
| TC-13 | private/loopback/link-local IP 拒否 | 解決後 IP が禁止クラスなら例外 | `TestMetadataAndPrivateIP` ✅ |
| TC-14 | DNS rebinding 対策 | 解決結果に禁止 IP が1つでもあれば例外 | `TestDnsRebinding` ✅ |
| TC-15 | IPv6（::1 / fc00::/7 / fe80::/10 / IPv4-mapped）拒否 | 例外 | `TestIPv6` ✅ |
| TC-16 | リダイレクト各 hop の再検証 | allowlist 外/メタデータへのリダイレクト拒否、許可 host への追従のみ可、ループは上限で打ち切り | `TestRedirectRevalidation` ✅ |
| TC-17 | パーサ二次 fetch の遮断 | img/iframe/script の src を取得しない・本文テキストのみ抽出 | `TestParserSecondaryFetch` ✅ |
| TC-18 | host 別 rate limit + 短 TTL キャッシュ | キャッシュ命中で再取得しない、間隔超過で例外 | `TestCacheAndRateLimit` ✅ |
| TC-19 | SourceSelect topic フィルタ | topic / 'all' タグのみ選択 | `unit/test_service_steps.py::TestSourceSelect` ✅ |
| TC-20 | RiskClassify low/medium/high | キーワードでリスク分類 | `unit/test_service_steps.py::TestRiskClassify` ✅ |
| TC-21 | 引用実在再照合（捏造引用拒否） | fetched_context に無い url / allowlist 外 url の引用をブロック | `unit/test_post_process_node.py::test_fabricated_citation_not_in_fetched_blocked / test_off_allowlist_citation_blocked` ✅ |
| TC-22 | no_sources_available フォールバック免除 | 引用ゼロでも fallback は S-3 通過（RETRY ループ防止） | `unit/test_post_process_node.py::TestS3FallbackExemption` ✅ |
| TC-23 | 全取得不可時の安全フォールバック | 捏造せず「現時点で情報取得不可」を返す | `unit/test_main_node.py::test_retry_exhausted_falls_back` + integration ✅ |
| TC-24 | 一時失敗の RETRY（上限付き） | transient 失敗で status=retry, retry_count を加算 | `unit/test_main_node.py::test_transient_failure_retries_and_increments_retry_count` ✅ |
| TC-25 (F-1) | 解決 IP のピン留め契約 | 解決した安全 IP が transport の接続先として渡る（再解決なし）。HTTPS は SNI/証明書は host 名で検証 | `unit/test_web_fetch_ssrf.py::TestIPPinningContract`（`test_pinned_ip_is_passed_to_transport` / `test_default_transport_http_connects_to_pinned_ip` / `test_default_transport_https_wraps_with_original_hostname`）✅ |
| TC-26 (F-1) | rebind 検出 | resolver が安全 IP + 禁止 IP を返すと transport 到達前にブロック | `unit/test_web_fetch_ssrf.py::TestIPPinningContract::test_rebind_second_resolution_forbidden_never_reaches_transport` ✅ |
| TC-27 (F-2) | 偽マーカー注入の非免除 | LLM 出力に `[no_sources_available]` を混入しても、構造化 state フラグが無ければ S-3 は免除せずブロック | `unit/test_post_process_node.py::TestS3FallbackExemption::test_injected_marker_*` / `test_flag_set_but_context_nonempty_still_enforces` ✅ |
| TC-28 (F-3) | S-3 config allowlist 交差 | 引用 host が fetched_context には在るが config allowlist に無い → ブロック | `unit/test_post_process_node.py::TestS3ConfigAllowlistCrossCheck` ✅ |
| TC-29 (bypass) | 非10進 IPv4 表記 | 8進(0177.0.0.1)/16進(0x7f.0.0.1)/整数(2130706433) が禁止クラス扱い | `unit/test_web_fetch_ssrf.py::TestNumericIPForms` ✅ |
| TC-30 (bypass) | host 大文字化 / 末尾ドット | `FSA.GO.JP.` 等の正規化で allowlist 回避不可（共通 `normalize_host`） | `unit/test_web_fetch_ssrf.py::TestHostNormalizationBypass` ✅ |
| TC-31 (bypass) | redirect→private/metadata | Location が private/メタデータ（数値表記含む）へ向かう hop をブロック | `unit/test_web_fetch_ssrf.py::TestRedirectToPrivateIP` ✅ |

### IPv4-only 環境での pin 選択回帰テスト
- resolver が IPv6 を先に返しても、公開 IPv4 があれば IPv4 を transport に渡す。
- IPv4 が無い場合は、公開 IPv6 を transport に渡す。
- 同一アドレスファミリ内では数値ソート順の先頭を選び、resolver の返却順に依存しない。
- IPv4 と IPv6 の全解決結果を pin 選択前に SSRF 検査する。
- 混在結果に禁止 IP が一件でも含まれれば、transport 到達前に取得全体を拒否する。
- 対応テスト: `TestIPPinningContract::test_ipv4_is_preferred_when_resolver_returns_ipv6_first` ほか2件。

## Proof-of-Boundary Tests（必須）

| PB-ID | 境界 | テスト | 期待結果 | 実装 |
|-------|------|------|----------|------|
| PB-1 | BaseNode → AuditSink | `emit_trace_event`（S-4）が応答ごとに発火 | サイレント失敗なし | `unit/test_post_process_node.py::TestS4Audit` ✅ |
| PB-2 | State シリアライズ | invoke 後の State が primitives のみ | JSON シリアライズ可能（datetime/Pydantic なし） | `proof_of_boundary/test_invoke_order.py::test_state_is_json_serializable` ✅ |
| PB-4 | Import isolation | src/ が Level 0 を import しない | AST スキャン 0 違反 | `proof_of_boundary/test_import_isolation.py` ✅ |
| PB-5 | Checkpoint 安全性 | credential/InvocationContext なし | 検査 PASS | `proof_of_boundary/test_state_safety.py` ✅ |
| PB-6 | invoke 実行順序 | 固定 backbone を pre→main→post の順で実行 | `node_history` が initialize→pre_process→main→post_process→finalize | `proof_of_boundary/test_invoke_order.py::test_backbone_order` ✅ |

> 備考: PB-3（実外部サービス接続）は本テンプレートでは「実ネットワークアクセスをテストで行わない」方針のため、transport 注入シームによるオフライン検証（TC-10〜18）で代替する。実 STG での invoke 確認は STG 検証時（docs/07）に実施する。

## テスト実行サマリ

```bash
source .venv/bin/activate
python -m pytest tests/ -v
python -m pytest tests/proof_of_boundary/ -v
```

- 総数: 87 / Pass: 87 / Fail: 0 / Skip: 0
- カバレッジ: src/ 86%（コアモジュール 89〜100%）
