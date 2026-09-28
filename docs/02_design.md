# テンプレート設計仕様書 — CMN-C1-084

AI Agent Lifecycle & Governance Policy Q&A Agent — **Live Web Fetch + LLM コンテキスト注入**（Cat 1）。

## AgentCore アーキテクチャ上の位置づけ

- **Agent Class**: `GovernancePolicyQAAgent`
- **L1 Base**: `AgentBaseGraph`（L1 直接継承 — **Level 2 基底クラスなし**。v0.16 の
  フレームワーク変更で L2→L3 継承が廃止されたため、本テンプレートは L1 フレームワーク
  グラフを直接継承する。`sample/chat_agent` のリファレンス構成に倣う）。
- **三層分離 (Three-Layer Separation)**:
  - State: flat TypedDict 合成（`src/schemas/state.py`、`AgentState` を継承。Pydantic 不可 — msgpack 非互換）
  - Node: L1 継承（Template Method: `execute(self, state: dict) -> dict` のみ override）
  - Graph: 合成（`register_nodes()` が固定スロット `pre_process / main / post_process` を埋める）

> **Backbone マッピング（実装上の重要点）**: Cat 1 は固定 5 ノード backbone
> `initialize → pre_process → main → post_process → finalize` を使う。提案書の 7 ステップ
> 論理ガバナンスフローは、この固定 backbone の **上に写像** する — グラフノードは追加しない。
> `main` がライブ取得のサブステップを内部でオーケストレーションする
> （Cat 1 リファレンス実装と同パターン）。単一の L1 直接グラフを維持する。

| 論理ステップ（提案書） | Backbone スロット | 実装場所 |
|---|---|---|
| 1. QueryNormalize | pre_process | `PreProcessNode.execute`（+ S-2 入力ゲート） |
| 2. PolicyTopicClassify | pre_process | `PreProcessNode` → `topic` |
| 3. SourceSelect | main | `MainNode` → `SourceSelectStep`（topic で allowlist をフィルタ） |
| 4. WebFetchAndExtract | main | `MainNode` → `WebFetchService`（並列 fetch + HTML/PDF 抽出 + 短 TTL キャッシュ） |
| 5. RiskClassify | main | `MainNode` → `RiskClassifyStep`（low/medium/high） |
| 6. AnswerGenerate | main | `MainNode` → `AnswerGenerateStep`（LLM、引用 + fetch タイムスタンプ） |
| 7. S-3 Security Gate | post_process | `PostProcessNode._security_gate_output`（引用整合性 / allowlist 違反 / PII） |

## アーキテクチャ概要

### ノード構成 (Node Configuration)

| Node | 責務 | Input State | Output State | 継承/Override |
|------|------|-------------|--------------|---------------|
| initialize | schema_version, session_id, trust_level | user_input | （framework デフォルト） | InitializeNode（default） |
| pre_process | S-2 入力ゲート；クエリ正規化；ポリシートピック分類 | user_input, input_context | validated_input, topic, enriched_context | FunctionNode → execute() |
| main | SourceSelect → WebFetchAndExtract → RiskClassify → AnswerGenerate | validated_input, topic | selected_sources, fetched_context, risk_label, draft_answer | FunctionNode → execute() |
| post_process | S-3 出力ゲート；引用付き回答 + リスクラベルの組み立て | draft_answer, fetched_context, risk_label | result | FunctionNode → execute() |
| finalize | response_metadata, total_time_ms | result | （framework デフォルト） | FinalizeNode（default） |

### データフロー (Data Flow)

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
                                            ↓ (retry, max 3: 一時的 fetch / rate-limit)
                                          pre_process
```

- **Retry ルート**: `main` は一時的 fetch 失敗（rate-limit / timeout）時に
  `AgentStatus.RETRY` を返し、framework が `pre_process` から再試行する（max_retry=3）。
- **Error ルート**: 空/不正クエリ → `pre_process` が `AgentStatus.ERROR` を返す
  （以降の fetch なし）。リトライ後も全ソース取得不可 → `main` は安全な
  「現時点の情報を取得できません」結果（`no_sources_available` マーカー付き）を返し、
  決して捏造した回答を返さない。このフォールバックは S-3 の引用必須チェックの対象外
  （§セキュリティ設計 S-3 参照）とし、引用ゼロでも RETRY ループに陥らせない。

### State 定義 (State Definition)

| Field | Type | 目的 | 必須 |
|-------|------|------|------|
| validated_input | str | サニタイズ済みガバナンスクエリ（S-2 後） | yes |
| enriched_context | dict[str, Any] | {source, channel} — pre_process 後は read-only | yes |
| topic | str | deployment / access / risk / data / compliance | yes |
| selected_sources | list[dict[str, Any]] | [{url, title, topic}] — allowlist から選択 | yes |
| fetched_context | list[dict[str, Any]] | [{url, fetched_at, excerpt}] — 回答の根拠 | yes |
| risk_label | str | low / medium / high（問い合わせアクティビティの） | yes |
| draft_answer | str | S-3 ゲート前の LLM 回答 | yes |
| result | str | 最終的な引用付き回答 + リスクラベル（S-3 後） | yes |

**State 制約（必須）:**
- flat TypedDict のみ（primitives + JSON シリアライズ可能型。`datetime` 不可 —
  `fetched_at` は ISO-8601 **文字列** で保持）。
- JWT・API キー・credential を State に入れない（checkpoint DB 漏洩）。
- InvocationContext は `config["configurable"]` 経由のみ（State に入れない）。
- Pydantic モデル・dataclass・任意 Python オブジェクト不可（msgpack 非互換）。

## フレームワーク活用 (Framework Utilization)

### 利用する Shared コンポーネント
- [x] InvocationContext (correlation_id, session_id, permissions) — `config` 経由
- [x] AuditSink (`_emit_trace_event`) — post_process で emit（引用 + リスクラベル + ソース URL）
- [x] ConnectionPolicy（retry/timeout 戦略）— fetch timeout + 指数バックオフ
- [x] SecurityViolationError — allowlist 違反 / SSRF 試行時に raise
- [x] `_security_gate_input()`（S-2、PII 検出 — 必須）— PreProcessNode 内
- [x] `_security_gate_output()`（S-3、コンテンツ安全性 — 必須）— PostProcessNode 内

### 合成パターン (Composition Pattern)

- **パターン**: Standalone（単一の L1 直接 `AgentBaseGraph`）。ライブ取得のサブステップは
  `MainNode.execute()` 内でオーケストレーションされる素の service/step オブジェクトであり、
  **独立したグラフノードではない**（Cat 1 固定 backbone を維持。Cat 1 リファレンス実装を踏襲）。
- **合成ターゲット**: なし（subgraph / RemoteAgentNode なし）。
- **エラー伝播戦略**: `main` 内で処理（一時的なら RETRY、枯渇時は安全フォールバック）。
  ERROR は fetch 前にショートサーキット。

### セキュリティ設計 (S-1…S-5) — Live Web Fetch 固有

- **S-1 trust**: `required_trust_level = VERIFIED_EXTERNAL`。`BaseNode.__call__()` が
  自動強制（context 不在 = default-deny）。`__pre_invoke__` の override なし。
- **S-2 入力ゲート**（PreProcessNode）: 空/過大クエリを拒否。入力された質問を
  ログ記録・LLM 送信の前に PII スクラブ。
- **SSRF 防御（本テンプレートの核）**: `WebFetchService` は host が
  `config.agent.source_allowlist` に一致する URL **のみ** を取得する。拒否対象:
  private/loopback/link-local IP、クラウドメタデータエンドポイント (169.254.169.254)、
  `https`/`http` 以外のスキーム（`file://`, `gopher://`, …）、allowlist 外へ出る
  リダイレクト。host ごとの rate limit + 短 TTL キャッシュ（5〜15 分）。
  - **DNS rebinding 対策**: ホスト名 → IP 解決を fetch 時に行い、**解決後の IP が
    禁止クラスでないことを接続直前に検証**する（TOCTOU 回避: 解決した IP に対して
    接続をピン留めし、解決結果の使い回しをしない）。**リダイレクトの各 hop ごとに
    host allowlist 照合と IP クラス再検証を再実行**する（最終 URL だけ見ない）。
  - **IPv6 も対象**: loopback `::1`、ULA `fc00::/7`、link-local `fe80::/10`、
    IPv4-mapped IPv6（`::ffff:169.254.169.254` 等）を private/メタデータ相当として拒否。
    マルチスタック環境で IPv4 専用フィルタにならないようにする。
  - **メタデータ v2 / 各クラウド**: 169.254.169.254 に加え、GCE メタデータ
    (`metadata.google.internal`)、IMDSv2、Azure/その他クラウドのメタデータ host を拒否。
  - **パーサ側の二次リクエスト遮断**: HTML/PDF 抽出は **外部エンティティ無効化（XXE 対策）**、
    リモートリソースの自動取得（画像・iframe・PDF 内 URL アクション・RDFa リンク等）を
    **行わない**。抽出はテキスト本文に限定し、パーサ起因の二次 fetch を発生させない。
- **S-3 出力ゲート**（PostProcessNode）: 引用（`url` + `fetched_at`）を欠く主張を
  ブロック。allowlist 外 URL を参照する出力を拒否。credential / PII スキャン
  （`apply_s3_gate`）。`temperature: 0.0`、引用必須プロンプト。
  - **引用の実在再照合（捏造 citation 防止）**: 文字列パターンで引用有無を見るだけでは
    不十分なため、出力中の各引用 `url` が **`fetched_context` に実在する** こと、かつ
    **その `url` が `source_allowlist` に属する** ことを再照合する。LLM が生成した
    ダミー引用（fetch していない URL・allowlist 外 URL）はゲートで拒否する。
  - **安全フォールバックの扱い（再試行ループ防止）**: 全ソース取得不可時に `main` が返す
    「現時点の情報を取得できません」結果は **引用を持たない正規の応答**であり、S-3 の
    引用必須チェックの**対象外（whitelist）**とする。`result` に `no_sources_available`
    マーカーを立て、ゲートはこのマーカー付き応答を「引用ゼロでも合格」として通す
    （引用必須に永久に弾かれて RETRY ループに陥らないようにする）。
- **S-4 audit**: `_emit_trace_event` が呼び出しごとに query topic、選択ソース URL、
  fetch タイムスタンプ、リスクラベルを記録。
- **S-5**: `__init_subclass__` JWT 検出 — 自動（framework）。

## Import Isolation 確認
- [x] テンプレートは agenticstar-platform SDK（Level 0）を import しない
- [x] import 対象: `framework/`（graph, nodes, schemas, secrets, security）と `src/` のみ

## 設計判断記録 (Design Decision Record)

| 判断 | Option A | Option B | 採択 | 根拠 |
|------|----------|----------|------|------|
| KB アクセス | Vector RAG（embed + re-index） | **Live Web Fetch + コンテキスト注入** | **B** | URL 列挙可能・高頻度更新コーパス。KB 陳腐化ウィンドウゼロ。再インデキシング運用コストなし |
| L1 base type | **AgentBaseGraph** | AutonomousBaseGraph | **A** | 固定パイプラインであり自律ループではない（Cat 1） |
| サブステップ配置 | グラフノード追加 | **MainNode 内の service/step オブジェクト** | **B** | Cat 1 固定 5 ノード backbone を維持。単一 L1 直接グラフ（Cat 1 リファレンス実装のパターン） |
| URL 安全性 | オープン fetch | **Config allowlist + SSRF denylist** | **B** | SSRF 制御は必須。allowlist がトラスト境界。DNS rebinding 再検証 / IPv6・メタ v2 拒否 / パーサ二次 fetch 遮断まで含む |
| ハルシネーション制御 | 自由形式 LLM | **引用必須 + temperature 0.0 + S-3 ゲート** | **B** | `url` + `fetched_at` なき主張を許さない。引用は `fetched_context`・allowlist と再照合（ダミー引用拒否）。`no_sources_available` フォールバックのみ引用必須を免除。監査可能 |

## スコープ外 (Out of scope)（本テンプレート）
- Vector DB 構築 / 再インデキシング（設計上の意図）。
- 自律的 URL 探索（Cat 3 ReAct）— allowlist は運用側が精選する。
- 文書生成 / メモリ書き戻し — 別テンプレート（単一責任）。
