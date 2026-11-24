# Replay timers

A Replay timer lets fast mode shorten a specific wait in Target while preserving
the dependencies and input order of a recorded Case. Target uses the independent
[brz-replay SDK](https://github.com/we-breeze/replay) at the same call site in
both environments. Add the ordinary Cargo dependency:

```toml
[dependencies]
brz-replay = "0.1"
```

The build environment chooses behavior. Leave `BRZ_REPLAY_TIMER_SOCKET` unset
for normal development and production builds. Those binaries always use
`tokio::time::sleep_until` with the original deadline. Setting the variable
during a Replay build compiles in the timer protocol, using its value as the
default socket address. For a Replay binary, a runtime value can override that
address. The active Case controls planned waits and directs other waits to
their original Tokio deadlines.

For the managed Target container, build with its fixed in-container path:

```bash
BRZ_REPLAY_TIMER_SOCKET=/traffic-e2e/replay/timer.sock cargo build --release
```

## Plan a Case

Choose a wait site and a logical stream identity that Target can report. Count
the wait's occurrences from one for that site and stream. Use the application's
last processed input ordinal for `consumed_through`, or zero when the wait has
no preceding input. An SSE frame is application input after parsing and
handling. A network read or write receipt alone cannot establish that position.

Create a JSON plan that binds the wait to the **event sequence number of the
first recorded dependency request** the wait enables. Use a Case with a granular
event sequence and select an occurrence whose preceding input and later input
have distinct recorded delivery boundaries. A command name or timestamp alone
cannot identify the wait. The original Source evidence stays unchanged.

```json
{
  "cases": {
    "case-id": [
      {
        "site": "stream.flush",
        "stream": "response-1",
        "occurrence": 1,
        "consumed_through": 3,
        "before_request": 42
      }
    ]
  }
}
```

Replay validates that each anchor is a request in that Case's prepared sequence.
It wakes the registered wait when the sequence reaches the request. The SDK
returns from the wait and reports completion through the timer socket. Replay
then admits the actual matching request. Later recorded events continue to
follow the existing sequence, including any separate reply delivery receipts.
Reports expose `timer_events` for registration, wake, completion and
cancellation, with offsets from Case activation. Losing the timer socket or the
active Case invalidates the wait. A planned request stays gated if its wait was
cancelled before completing.

## Run Replay

For a locally launched Target, use a dedicated socket in a private directory.
Pass its absolute path as `BRZ_REPLAY_TIMER_SOCKET` to Target:

```bash
traffic-e2e replay --no-intercept --stream-timing fast \
  --timer-plan timers.json --timer-socket /tmp/replay-run/timers.sock CASE_DIR
```

For managed fast Replay, set `TRAFFIC_E2E_REPLAY_TIMER_PLAN` to the plan path
before starting the attempt and build the Replay Target with the socket
variable above. The runner resolves relative paths against the
Target root, includes the plan bytes in the Replay identity, and freezes the
plan at launch. It mounts only the dedicated timer socket into the Target
container and sets `BRZ_REPLAY_TIMER_SOCKET` there. Keep the same plan bytes
available when verifying the attempt's identity.

Session Replay uses fast timing with zero recorded intervals. For a managed
Session set the same plan environment variable and run `backend-rewrite session
run`. Direct Session Replay uses `traffic-e2e replay --session-events` with
`--timer-plan` and `--timer-socket`. A Session plan uses `cases.session` for
the scope. See [Source session regression](session-regression.md).

Target passes the active Case ID, site, stream, occurrence and consumed ordinal
to `brz_replay::tokio::time::sleep_until`. Keep one pinned Future per logical
wait when using `tokio::select!`. A wait without a matching plan in the active
Case uses its ordinary Tokio deadline.

Strict Replay still requires every recorded APPEND, EXPIRE and GET to match.
Combining writes, dropping a poll round or changing the order remains visible
to normal matching. Use this feature with providers that can replay the
recorded sequence. The built-in finite HTTP provider currently rejects SSE
dependency recordings.
