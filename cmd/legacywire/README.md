# legacywire tool

This tool emits a golden snapshot of the **Juju 3.6 ("legacy") wire-struct
signatures** JIMM serves to, or accepts from, 3.6 clients
(`internal/jujuapi/testdata/legacy_wire_shapes.txt`).

The snapshot guards the one drift class that facade-version negotiation cannot
catch: a juju dependency bump that silently renames a field (e.g.
`owner-tag` → `qualifier`) or drops a `*Legacy` struct at a fixed facade
version. The set of types is defined in `internal/jujuapi/legacywire`.

## Regenerate

```bash
make update-golden
```

Or run the generator directly:

```bash
go run ./cmd/legacywire -o internal/jujuapi/testdata/legacy_wire_shapes.txt
```

It is also wired into `go generate ./internal/jujuapi`, so `make generate`
recreates it too.

## Guard

`TestLegacyWireShapesGolden` (in `internal/jujuapi`) fails if the committed file
no longer matches the current structs, and CI's `verify_generated` job fails if
the committed file is out of date. When the change is intentional, regenerate
and commit.
