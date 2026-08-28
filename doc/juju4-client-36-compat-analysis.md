# Using the juju 4.x API client against 3.6 controllers: compatibility analysis

Date: 2026-06-12
Scope: what happens if JIMM upgrades its `github.com/juju/juju` dependency to 4.x,
keeps using the juju 4 typed API client in `internal/jujuclient` to talk to 3.6
controllers, and translates results back to the 3.6 wire format for 3.6 CLI clients.

Verified against: JIMM's pinned juju (`v0.0.0-20260325121537-78832a31ad6b`, tip of 3.6)
and the juju `4.0` branch as of 2026-06-12.

## 1. Why two juju versions can't be imported at once

A Go build can contain only one version of a module path. Both juju `main` and
`4.0` still declare `module github.com/juju/juju` (no `/v4` suffix), so JIMM can
link exactly one juju version. The realistic strategy is therefore: import juju
4.x, use its typed client everywhere, and rely on the 4.x client's built-in
3.6 compatibility (which exists because the juju 4 CLI itself must manage and
migrate 3.6 controllers).

## 2. Facade version negotiation: 3.6 server vs 4.0 client

Every facade `internal/jujuclient` uses has a non-empty version intersection:

| Facade (JIMM's usage) | 3.6 server offers | 4.0 client supports | Negotiated |
|---|---|---|---|
| Admin (Login — hand-rolled by JIMM) | 3 | n/a | 3 |
| Pinger | 1 | 1 | 1 |
| ApplicationOffers | 4, 5 | 5, 6 | 5 |
| Client (Status) | 6–8 | 8 | 8 |
| Cloud | 7 | 7, 8 | 7 |
| Controller | 11, 12 | 12, 13, 14 | 12 |
| ModelConfig | 3 | 3, 4 | 3 |
| ModelManager | 9, 10 | 9, 10, 11 | 10 |
| ModelUpgrader | 1 | 1, 2 | 1 |
| Storage | 6, 7 | 6, 7 | 7 |
| MigrationTarget | 1–6 | 4–7 | 6 |
| ModelSummaryWatcher | 1 | 1 | 1 |

The 4.0 typed clients carry working legacy code at those versions:

- `api/client/modelmanager`: `createModelCompat`, `modelInfoCompat`,
  `listModelsCompat`, `listModelSummariesCompat` keyed on `BestAPIVersion() < 11`,
  using `params.*Legacy` structs that still speak `owner-tag`.
- `api/controller/migrationtarget`: `< 7` branch using `MigrationModelInfoLegacy`,
  `< 2` branch for `Activate`.
- `api/client/applicationoffers`: legacy filter conversion for `< 6`; `Offer`
  still sends `OwnerTag`.
- `Controller.CloudSpec` is served by 3.6 (embedded `CloudSpecer` at v11/12).
- `UpgradeModelParams`, `ModelAbstract`, all Storage and Cloud v7 structs:
  wire-identical between 3.6 and 4.0.

Conclusion: **no `jujuclient` method needs raw reimplementation today.** JIMM's
hand-rolled calls (`Admin.Login` v3, `Pinger.Ping` v1, raw
`MigrationTarget.Prechecks`/`AdoptResources` pinned to v6) are unaffected.

## 3. Serving 3.6 CLIs from JIMM built on juju 4

Only the facades JIMM itself implements need translation; model connections go
through `internal/rpcproxy` as raw frames (3.6 CLI ↔ 3.6 controller directly).

JIMM-implemented facades (versions advertised by `setupFacades`): Admin,
Pinger 1, ModelManager 9/10, Cloud 7, Controller 11/12, ApplicationOffers 5,
ModelConfig 3, ModelUpgrader 1, UserManager 3, MigrationTarget 6,
ModelSummaryWatcher 1, JIMM 4 (custom).

JIMM owns its RPC layer (`internal/rpc`), so handlers can declare any structs.
For 3.6-format requests/responses, switch the affected handler signatures from
`jujuparams.X` to `jujuparams.XLegacy` (or JIMM-owned copies of the 3.6 structs).

### ModelInfo round trip (owner `alice@external`), verified hop by hop

1. 4.0 client → 3.6 controller: `modelInfoCompat` decodes the response into
   `params.ModelInfoLegacy` (`owner-tag` intact).
2. Compat conversion: every field copied 1:1; `ParseUserTag("user-alice@external")`
   → `QualifierFromUserTag` → `Qualifier = "alice@external"`. Lossless:
   `QualifierFromUserTag(u)` is literally `Qualifier(u.Id())`.
3. JIMM → 3.6 CLI: `OwnerTag = names.NewUserTag(qualifier).String()` →
   `"user-alice@external"`, byte-identical to the original.

## 4. Complete wire-format diff (every jujuparams type used by internal/jujuapi)

All ~140 `jujuparams` types referenced by `internal/jujuapi` were diffed by JSON
tag signature between 3.6 and 4.0, including transitive sub-structs of
`FullStatus`, offer details, and summaries. Full list of differences:

### Owner→qualifier renames (lossless single-field transforms; Legacy twins exist)

| Struct | Change |
|---|---|
| `ModelInfo` | `owner-tag` → `qualifier` |
| `ModelCreateArgs` | `owner-tag` → `qualifier` (request direction) |
| `Model` (in `UserModelList`) | `owner-tag` → `qualifier` |
| `ModelStatus` | `owner-tag` → `qualifier` |
| `ModelSummary` | `owner-tag` → `qualifier` |
| `MigrationModelInfo` | `owner-tag` → `qualifier` |
| `OfferFilter` | `owner-name` → `model-qualifier` (request direction) |

### Dropped deprecated fields (accepted as irrelevant for JAAS)

- `ModelInfo`: `default-series`, `default-base`, `sla`
- `ModelSummary`: `default-series`, `sla`
- `ModelSLAInfo`: type removed
- `ModelMachineInfo`: `has-vote`, `wants-vote`, `ha-primary` (controller models
  only — JIMM hides controller models from users)
- `FullStatus` tree: `ModelStatusInfo.meter-status`/`sla`,
  `ApplicationStatus.meter-statuses`; `MeterStatus` type removed

### Additive-only fields (omitempty; leave unset for 3.6 output)

- `ModelInfo`/`ModelCreateArgs`: `target-controller` (JAAS-specific, added by juju)
- `MachineStatus`: `cluster-role`

### Everything else: byte-identical

All Cloud facade structs (v7), all credential structs, ApplicationOffers
response types (`ApplicationOfferDetailsV5`, `ApplicationOfferAdminDetailsV5`,
`ConsumeOfferDetails`, `OfferConnection`, `RemoteEndpoint`, `OfferUserDetails`),
UserManager `UserInfo`, `LoginRequest`/`LoginResult`, `ModelUserInfo`,
model defaults, access-modification requests, `InitiateMigrationArgs`/
`MigrationSpec`, controller config, summary-watcher types, destroy/upgrade/
credential-change args, generic envelopes (`Entities`, `ErrorResults`, ...).

**Conclusion: no conversion is hard or impossible.**

## 5. Caveats / follow-ups

1. **Legacy structs are temporary in juju.** The `*Legacy` params and the
   `< 11`/`< 7` client branches exist only while juju 4.x supports managing 3.6
   controllers and will be deleted later. They are plain data structs — copy
   them into a JIMM-owned package (e.g. `internal/jujuapi/params36`) to decouple
   from juju's deletion schedule. The same seam supports serving both wire
   formats later (advertise e.g. ModelManager 10 legacy + 11 qualifier).
2. **Qualifier == user id is an implementation detail of 4.0.** Juju 4 allows
   non-user qualifiers (`staging`, ...). Data from 3.6 controllers always
   round-trips (those models have real owners), but prefer JIMM's DB as the
   source of truth for owner-tag rather than parsing qualifiers. A 4.x model
   with a non-user qualifier has no faithful `owner-tag` representation for a
   3.6 CLI — inherent to the data, not the translation layer.
3. **Same-version struct drift can recur in future 4.x releases.** All findings
   verified against the 4.0 branch on 2026-06-12. Recommended: commit a golden
   file of the wire signatures of the types in §4 and diff it in CI on every
   juju dependency bump, so silent field drops fail loudly.
4. **Mechanical migration cost** (separate from wire compat): every 4.0 typed
   client method takes a `ctx`, `CreateModel`'s signature changed
   (`names.UserTag` instead of owner string), and `internal/jimm`/`dbmodel`
   code referencing `OwnerTag` on params structs must move to the Legacy
   structs or qualifier fields.
