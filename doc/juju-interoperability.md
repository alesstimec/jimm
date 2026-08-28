# Juju client interoperability

JIMM sits in front of a fleet of Juju controllers that may span major
versions (3.6 and 4.x). This document describes how JIMM decides which
controllers and models a given Juju client may interact with, where that
decision is enforced, and what is deliberately left unrestricted. It
reflects the approved "JIMM and Juju Interoperability" spec (approved
2026-06-25) and the implementation as shipped.

Juju 2.9 clients are out of scope: they are not supported against JIMM.

## The compatibility rule

A client may interact with controllers — and the models hosted on them —
whose **major version is less than or equal to the client's reported major
version**.

This is Juju's own [cross-version compatibility
contract](https://canonical.com/juju/docs/juju-cli/3.6/reference/juju/juju-cross-version-compatibility/)
applied across a fleet: components of the same major series are compatible
with each other (Juju's per-facade version negotiation absorbs the
finer-grained differences), while across major series a newer client can
operate older controllers but an older client cannot operate newer ones.
Concretely:

|                          | 3.6-hosted model | 4.x-hosted model        |
|--------------------------|------------------|-------------------------|
| **Juju 3.6 client**      | compatible       | rejected                |
| **Juju 4.x client**      | compatible       | compatible              |
| **non-reporting client** | compatible       | rejected (treated as 3.6) |

- The client reports its version via the `X-Juju-ClientVersion` header on
  the main API websocket dial.
- A client that reports no version, or an unparseable one, is treated as a
  **Juju 3.6** client. Juju 3.6 clients predate the header, so this is the
  correct resolution for them, and it fails closed for anything else.
- The header is client-asserted. It gates UX and routing only — it is
  **not** an authorization input; all authorization happens at login as
  usual.

### How the version reaches JIMM

Juju clients have always sent `X-Juju-ClientVersion` on stream and
plain-HTTP connections, but the main API websocket dial carried no headers
until juju/juju#22794 (commit `cf559c20`, first tagged in v4.0.13). JIMM is
the first consumer of the header on that connection.

JIMM extracts the header at the websocket upgrade for every websocket
endpoint (`internal/jimmhttp/websocket.go`) and carries it in the request
context (`jimmhttp.ClientVersionFromContext`), so both enforcement points
below read the same value.

## Enforcement point 1: model placement

When a client creates a model, JIMM only places it on a controller whose
major version is ≤ the client's reported major version.

- The cap is derived once per connection by
  `highestControllerVersionForClient` (`internal/jujuapi/controllerroot.go`):
  the major component of the reported version, or 3 when the version is
  absent or unparseable.
- It is applied in the shared `createModel` path, covering both the
  ModelManager v10 (3.6 client) and v11 (4.x client) facades, and in the
  JIMM facade's `AddModelToController` (used by the jaas plugin), where an
  explicitly named controller must also satisfy the cap.
- Controller eligibility filtering, the explicit-controller check and the
  client-facing error messages live in the model-creation builder
  (`MaxControllerMajorVersion`).

A controller whose agent version is unknown is not eligible for a capped
placement (fail closed).

## Enforcement point 2: the model proxy

JIMM proxies model API connections (`/model/{uuid}/api`, `/commands`) to
the hosting controller without translating the wire format, so a 3.6 client
talking to a 4.x-hosted model would otherwise fail deep inside operations
with obscure errors. Instead, the compatibility rule is applied up front,
at **user login** on the proxied connection
(`internal/rpcproxy/compatibility.go`):

- The connection is rejected when the major version of the model's hosting
  controller (which serves the model's API, and therefore determines
  compatibility — not the model's own agent version) exceeds the client's
  reported major version:

  > your Juju client is not compatible with model "prod" (4.0.2); please
  > upgrade your Juju client to interact with this model

- A hosting controller whose agent version is unknown is rejected fail
  closed, consistent with placement:

  > cannot establish that your Juju client is compatible with model
  > "prod": the hosting controller's version is unknown

- Connections to 3.6-hosted models are unrestricted; a 4.x-reporting client
  reaches everything.

The check applies to user logins only. Agent and anonymous logins are
redirected to, or handled by, the backing controller and never reach it.
Enforcement is always on; there is no configuration flag.

## What is deliberately not gated

- **Model listings.** `juju models` (and every other listing) shows all of
  a user's models regardless of compatibility. Discovery is unaffected;
  incompatibility surfaces only on interaction. This is a spec UX decision —
  do not "helpfully" filter listings by client version.
- **Stream endpoints** (`/log` and friends). Juju versions the log stream
  itself via a `version` query parameter that defaults to the legacy (3.6)
  format, so gating the stream would break something juju already made
  work. JIMM forwards the client's `X-Juju-ClientVersion` header when
  dialing the controller-side stream
  (`internal/jujuapi/streamcontrollerproxy.go`).

## Facade multi-versioning (background)

Independently of the version-driven gating above, JIMM's own controller
endpoint serves both the 3.6-era and 4.x-era versions of the facades it
implements, dispatching on the version each client negotiates — e.g.
ModelManager 10 and 11, ModelConfig 3 and 4, Controller 12 and 14,
ApplicationOffers 5 and 6, Admin 1–4. Where the request or response wire
shapes differ between eras, the older facade version translates. See
[add-new-facade.md](add-new-facade.md) for how facades are added.

The complete per-facade wire-format analysis — including why the 4.x API
client JIMM uses to talk to backing controllers remains compatible with 3.6
controllers — is in
[juju4-client-36-compat-analysis.md](juju4-client-36-compat-analysis.md).

The gating in this document is about *model* interaction: JIMM's own
controller-level facades work for both client generations, while
model-level traffic is proxied raw, which is exactly why the proxy check
exists.

## Deployment notes

- **Ingress must forward the header.** Any L7 proxy or ingress in front of
  JIMM must pass `X-Juju-ClientVersion` through on the websocket upgrade
  request. An ingress that strips it makes every client look unversioned
  (i.e. 3.6), locking 4.x clients out of 4.x-hosted models.
- **Client release requirement.** Enforcement is always on, so JIMM
  versions containing it should not serve production traffic until a
  *released* 4.x client sending the header (v4.0.13 or later) is available
  to users — an older 4.x CLI sends no header on the main dial and is
  treated as 3.6.

## Release verification checklist

The automated e2e suite (`testing/`, run by the E2E workflow against 3-only,
4-only and mixed fleets) covers the spec scenarios as follows:

- Native header path of the released 4.x client library (the same dialer a
  released CLI uses): `TestNativeClientVersionHeader`.
- Placement capping for unversioned/3.6/4.x clients:
  `TestModelPlacementByClientVersion`.
- Proxy gating, unfiltered discovery and ungated agent logins:
  `TestModelProxyClientCompatibilityJuju3Controller` / `...Juju4Controller`.

What the suite cannot exercise is the released **snap CLI binary** itself.
When validating a release, verify manually against a JIMM with a mixed
3.6/4.x fleet:

1. `juju add-model` from a released 4.x CLI (≥ 4.0.14) can land a model on
   a 4.x controller.
2. `juju add-model` from a 3.6 CLI lands only on 3.6 controllers.
3. A 3.6 CLI switched to a 4.x-hosted model gets the upgrade error on
   interaction (e.g. `juju status`), while `juju models` still lists the
   model.
4. A 4.x CLI can interact with models hosted on both controller
   generations.

## References

- "JIMM and Juju Interoperability" spec (approved 2026-06-25).
- [Juju component cross-version
  compatibility](https://canonical.com/juju/docs/juju-cli/3.6/reference/juju/juju-cross-version-compatibility/)
  — the upstream compatibility rules this document applies fleet-wide.
- juju/juju#22794 — client sends `X-Juju-ClientVersion` on the main API
  websocket dial (first tagged in v4.0.13).
- canonical/jimm#2058 — placement cap from the reported client version.
- canonical/jimm#2065 — client/model compatibility enforced in the model
  proxy.
