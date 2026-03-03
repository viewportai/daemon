# Viewport Daemon Configuration

## Precedence

Daemon runtime settings resolve in this order (later wins):

1. Built-in defaults
2. `~/.viewport/config.json` (`daemon.*`)
3. Environment variables (`VPD_*` / `VIEWPORT_*`)
4. CLI flags

Session config resolution is separate:

1. Framework built-ins
2. Agent defaults
3. Global defaults (`defaults`)
4. Directory overrides (`directories.<id>.config`)
5. Session launch overrides

## Runtime keys

`config.json`:

```json
{
  "daemon": {
    "listen": "127.0.0.1:7070",
    "profile": "local",
    "allowedHosts": ["localhost"],
    "allowedOrigins": ["localhost"],
    "authEnabled": false,
    "logFile": "~/.viewport/daemon.log",
    "relay": {
      "enabled": false,
      "endpoint": "wss://relay.example.test",
      "publicEndpoint": "wss://relay.example.test"
    }
  }
}
```

## Environment variables

- `VPD_LISTEN` / `VIEWPORT_LISTEN`
- `VPD_PROFILE` / `VIEWPORT_PROFILE`
- `VPD_ALLOWED_HOSTS` / `VIEWPORT_ALLOWED_HOSTS`
- `VPD_ALLOWED_ORIGINS` / `VIEWPORT_ALLOWED_ORIGINS`
- `VPD_AUTH` / `VIEWPORT_AUTH`
- `VPD_LOG_FILE` / `VIEWPORT_LOG_FILE`
- `VPD_RELAY_ENABLED` / `VIEWPORT_RELAY_ENABLED`
- `VPD_RELAY_ENDPOINT` / `VIEWPORT_RELAY_ENDPOINT`
- `VIEWPORT_HTTP_LOG_LEVEL`
- `VIEWPORT_MAX_WS_CLIENTS`

## CLI flags

- `--listen`
- `--profile`
- `--allowed-hosts`
- `--allowed-origins`
- `--auth`
- `--log-file`
- `--relay-endpoint`
- `--no-relay`

## Notes for relay phase

Current daemon config already carries relay keys and security profile semantics.
Relay transport, cryptographic peer identity, and remote identity binding are intentionally deferred to the relay phase.

## Validation guarantees

- `~/.viewport/config.json` is schema-validated with Zod.
- Malformed JSON or schema-invalid values fail fast with actionable errors.
- Unknown keys are rejected to prevent silent misconfiguration drift.
