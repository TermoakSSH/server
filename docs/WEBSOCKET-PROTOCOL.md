# WebSocket protocol

## Session terminal: `GET /api/v1/sessions/{id}/ws`

### Access

There are three ways in:

| How | Access |
|---|---|
| `Authorization: Bearer <token>` or `?access_token=<token>` | The owner joins as `owner`. An invited user joins with the permission of their share |
| `?share_token=<token>` | Link share. No account needed |
| `?role=host` | Only for `relay` sessions and only for the owner: the client that has the real terminal |

What each access level can do:

| Access | View | Type | Resize | Answer prompts | Close |
|---|---|---|---|---|---|
| `owner` | yes | yes | yes | yes | yes |
| `control` | yes | yes | yes | — | — |
| `view` | yes | — | — | — | — |

### Frames

- **Binary**: terminal bytes. From the server they are the output; from the
  client, what is typed.
- **Text**: JSON with a `type` field.

### Server to client

On connect, the server sends, in this order:

1. `{"type":"hello","session":{…},"you":{"id","name","access","role",…}}`.
2. A binary frame with the scrollback snapshot. If the session is still
   connecting, it arrives as soon as it becomes `running`.
3. From then on, the live output, with no gaps or duplicates relative to the
   snapshot.

Other messages:

| `type` | Fields | When |
|---|---|---|
| `status` | `status` | The state changes. `status.state` is `connecting` (with `message`), `running`, `host_offline` (relay without its host) or `closed` (with `exit_code` and `reason`) |
| `presence` | `viewers[]` | Someone joins or leaves |
| `resize` | `cols`, `rows` | The terminal size changes |
| `title` | `title` | The session is renamed |
| `prompt` | `prompt_id`, `kind`, `host`, `message`, `prompts[]`, `fingerprint?`, `key_type?` | Owner only. The server needs an answer: `kind` is `hostkey`, `keyboard_interactive`, `password` or `passphrase` |
| `prompt_done` | `prompt_id` | The prompt was answered, maybe from another device |
| `resync` | — | The client fell behind. A new snapshot follows and replaces the screen |
| `pong` | `ts` | Answer to `ping` |
| `error` | `message` | Error. If the share is revoked, an error arrives and the socket closes |

When the session ends, the server sends the last `status`, the remaining
output, and closes.

### Client to server

```json
{"type":"resize","cols":120,"rows":40}
{"type":"input","data":"ls -la\r"}
{"type":"prompt_answer","prompt_id":"…","accept":true}
{"type":"prompt_answer","prompt_id":"…","answers":["123456"]}
{"type":"ping"}
{"type":"close_session"}
{"type":"host_closed"}
```

- `input` is a text alternative to binary frames.
- `close_session` closes the session for everyone. Owner only.
- `host_closed` is only sent by the host of a relay session, when its local
  terminal ends.

If someone without permission sends a JSON message they are not allowed to
send, they get `{"type":"error"}` and the action is ignored. Binary frames
from a `view` viewer are dropped silently.

### Relay sessions

The host, connected with `?role=host`, sends the output of its local
terminal as binary frames and receives, also as binary, what viewers with
`control` access type. It also receives the `resize` requests. The server
connects to no host: it only relays and keeps the scrollback.

## User events: `GET /api/v1/events/ws`

Receive only, with user authentication. On connect:

```json
{"type":"hello","user":{…},"pending_approvals":[…]}
```

and then two kinds of messages:

```json
{"type":"ai","task_id":"…","seq":42,"event":{"type":"approval_requested","approval_id":"…","tool":"run_command","summary":"…","input":{…}}}
{"type":"session","notice":{"type":"session_shared","session":{…},"by":"Ana","team":"Ops"}}
```

| `ai.event.type` | Meaning |
|---|---|
| `status` | Task state: `queued`, `running`, `waiting_approval`, `completed`, `failed` or `cancelled` |
| `text` / `reasoning` | Chunks (`delta`) of the answer and of the reasoning summary |
| `reset` | Discard the text in progress: the provider failed and the turn is retried with the fallback |
| `notice` | Notice: retry, provider switch... |
| `tool_call` / `tool_result` | A tool call and its result |
| `approval_requested` / `approval_decided` | Approvals |
| `message` | Full message at the end of a turn |
| `usage` | Tokens and cost in micro-dollars (`cost_micros`) |
| `finished` | End of the task, with `result` or `error` |

| `session.notice.type` | Fields | Meaning |
|---|---|---|
| `session_opened` | `session` | One of your sessions was opened |
| `session_closed` | `session_id`, `reason?` | One of your sessions was closed |
| `session_shared` | `session`, `by`, `team?` | Someone shared a session with you. `by` is the name of who shared it; `team` is the name of the team it was shared through, and is absent for a direct share |
| `prompt_pending` | `session_id`, `prompt` | One of your sessions is waiting for an answer (known host, 2FA...) |

If the client falls behind, `{"type":"lagged","missed":n}` arrives. Then
fetch what was missed with `GET /ai/tasks/{id}/events?after=<last seq>`.
