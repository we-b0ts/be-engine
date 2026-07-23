# Remote Case Source

Use this reference only when the user supplies a remote IPv4 address instead of
a local case source. Remote acquisition materializes an immutable local case
source; it does not change the `recorded-e2e-cases` replay contract.

## Inputs And Helper

Require one canonical IPv4 address with four decimal octets in the range
`0..255`. Do not accept a scheme, port, path, hostname, IPv6 literal, shell
syntax, or embedded credentials. Construct:

```text
API_URL=http://<ipv4>:9090
```

Resolve `scripts/pluto-task.sh` relative to this skill directory and invoke it
by absolute path. Set `PLUTO_RS_DIR` to the canonical target repository path.
Do not search the source repository, target repository, current directory, or
`PATH` for another script with the same name.

The bundled helper retains `record`, `compare`, `stop`, `tasks`, `recordings`,
and `download` for task-service operations. Remote case acquisition MUST call
only `recordings` and `download`. Never start, compare, redeploy, or stop a
remote task merely to obtain a case source. Use the other commands only when
the user separately and explicitly requests that operation.

## Freeze One Snapshot

Set `API_URL` and call:

```bash
<absolute-skill-path>/scripts/pluto-task.sh recordings 200
```

Follow `next_before` with:

```bash
<absolute-skill-path>/scripts/pluto-task.sh recordings 200 <next_before>
```

until it is absent. The first page fixes the snapshot's upper boundary; later
recordings are outside this invocation. Require each page to be valid JSON and
reject repeated cursors, duplicate artifact IDs, malformed 14-digit IDs, or
entries whose required fields have incompatible types.

Normal migration candidates satisfy all of:

- `artifact_kind == "recording"`;
- `status == "completed"`;
- `downloadable == true`;
- `published_cases > 0`;
- `failed_cases == 0`.

Sort candidates by recording ID ascending. Retain running, failed, empty, and
comparison counts for diagnostics, but never select them for the normal remote
migration queue.

## Cache And Download

Use this default cache root:

```text
<target-parent>/traffic-e2e-remote-recordings/<ipv4>/
```

For one candidate ID, use:

```text
<cache-root>/<recording-id>/<recording-id>.tar.gz
```

Create only the exact cache directories needed. Download through the bundled
helper:

```bash
<absolute-skill-path>/scripts/pluto-task.sh \
  download <recording-id> <archive-path>
```

The helper writes through a `.part` file and refuses to overwrite an existing
path. Reuse an existing archive only after it passes every validation below;
never replace, merge, or repair an inconsistent cached artifact in place.

Before extraction:

1. compute and retain the archive SHA-256;
2. require a valid gzip-compressed tar archive;
3. require every member below one top-level directory named exactly as the
   recording ID;
4. reject absolute paths, `..`, symbolic links, hard links, devices, FIFOs,
   sockets, and other special entries.

Extract without preserving archive ownership or elevated permissions. Require
`recording-run.json` to match the selected ID, `completed` status,
`published_cases`, and zero failed cases from the frozen list entry.

Discover canonical case-source directories below the run root. A candidate
source contains published case directories with both `request.json` and
`expected-response.json`. Ignore `failed`, `staging`, `.replay`, `.partial`,
`.truncated`, and other recorder-internal directories according to
`recorded-e2e-cases`. Require the total discovered published-case count to equal
the frozen list entry. Preserve every downloaded file unchanged.

## Select The Oldest Unprocessed Recording

Confirm or initialize the target's stable `.traffic-e2e/e2e.yaml` before
asking the runner for status. For each frozen candidate in ascending order:

1. reuse or download and validate its cache;
2. discover all canonical case sources;
3. call `traffic-e2e status --target-root <target> --case-source <source>` for
   every source;
4. skip the recording only when every source has successful terminal runner
   state;
5. otherwise select that recording and stop scanning.

Missing, failed, interrupted, invalid, or unavailable runner state is not
processed. If cache or runner evidence was removed, conservatively materialize
or verify the recording again. Do not use a changelog, download receipt,
archive presence, helper exit status, migration ledger, response-only result,
or verified-exclude entry as processed evidence.

If no candidate remains, report that the frozen snapshot has no clean
unprocessed recording and perform no migration or delivery mutation.

## Handoff

For remote mode, retain and report:

- remote IPv4 address and derived API URL;
- frozen snapshot upper boundary;
- selected recording ID and remote metadata;
- cache root and archive SHA-256;
- every canonical local case source;
- excluded artifact counts and any failed recording IDs relevant to diagnosis;
- exact runner states and canonical replay evidence.

Remote acquisition is complete only when the artifact is safely materialized
and validated. Migration completion still requires every ordinary
`e2e-rewrite-migration` and `recorded-e2e-cases` gate.
