---
myst:
  html_meta:
    description: "Understand which Juju client versions can interact with which controllers and models in JAAS, and what to expect from incompatible combinations."
---

(juju-client-interoperability)=
# Juju client interoperability

JIMM manages a fleet of Juju controllers that may span major versions (3.6 and 4.x; Juju 2.9 is not supported). This document describes which controllers and models you can interact with depending on the version of your Juju client, and what to expect when a combination is not compatible.

## The compatibility rule

A Juju client can interact with controllers — and the models hosted on them — whose **major version is less than or equal to your client's major version**.

This follows Juju's own [cross-version compatibility contract](https://canonical.com/juju/docs/juju-cli/3.6/reference/juju/juju-cross-version-compatibility/): versions within the same major series are compatible with each other, and a newer client can operate older controllers, but an older client cannot operate newer ones. Concretely:

|                     | 3.6-hosted model | 4.x-hosted model |
|---------------------|------------------|------------------|
| **Juju 3.6 client** | compatible       | not compatible   |
| **Juju 4.x client** | compatible       | compatible       |

Note that Juju 4.x clients older than **4.0.13** do not yet report their version to JIMM and are treated as 3.6 clients. To work with 4.x-hosted models, use a client of version 4.0.13 or later.

## What this means in practice

**Adding models.** When you run `juju add-model`, JIMM automatically places the new model on a controller compatible with your client, so a model you create is always one you can use. If no compatible controller is available — or you explicitly ask for a controller that is newer than your client — the command fails with a message asking you to upgrade your client, for example:

```text
controller "prod-4" (version "4.0.13") is not compatible with your Juju client; please upgrade your client to use this controller
```

**Working with models.** Connecting to a model hosted on a controller newer than your client is rejected up front with a clear message, rather than failing in confusing ways partway through an operation:

```text
your Juju client is not compatible with model "prod" (4.0.2); please upgrade your Juju client to interact with this model
```

Upgrading your client resolves this; a 4.x client can work with models on both controller generations.

**Listing models.** `juju models` and other listings always show all of your models, including ones you cannot currently interact with. Incompatibility only surfaces when you try to use such a model.

**Controller-level operations.** Commands that talk to JIMM itself — logging in, listing models and offers, managing permissions, clouds and credentials — work for both 3.6 and 4.x clients regardless of the controllers behind JIMM.

## Notes for JAAS operators

These notes concern the deployment itself rather than day-to-day use of the `juju` CLI:

- Any L7 proxy or ingress in front of JIMM must forward the `X-Juju-ClientVersion` header on websocket upgrade requests. If the header is stripped, every client is treated as a 3.6 client and 4.x clients lose access to 4.x-hosted models.
- Clients that do not report a version are always treated as Juju 3.6 clients (this is the fail-safe default; 3.6 clients predate version reporting).
