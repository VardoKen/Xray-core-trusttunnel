# TrustTunnel Fork Documentation

Russian version: [README.ru.md](README.ru.md)

This directory contains the maintained documentation set for the TrustTunnel fork of Xray-core.

## Where To Start

Public fork documentation:

- Fork overview: [../README.md](../README.md)
- Configuration guide: [configuration.md](configuration.md)
- Russian configuration guide: [configuration.ru.md](configuration.ru.md)

Current source of truth:

- State: [current/current-state.md](current/current-state.md)
- Architecture: [current/architecture.md](current/architecture.md)
- Operations: [current/operations.md](current/operations.md)
- Validation: [current/validation.md](current/validation.md)
- Roadmap: [current/roadmap.md](current/roadmap.md)

## Documentation Layers

- `docs/current/*`
  - The only current source of truth.
  - Use this layer for actual behavior, supported paths, validated configs, and open tasks.
- `docs/history/*`
  - Historical development notes.
  - Use only to understand how the project reached the current state.
- `docs/migration/*`
  - Reconciliation and migration notes for older documentation sources.
- `docs/archive/*`
  - Retained but non-current material.

## Reading Order

For any TrustTunnel code, config, test, or runtime task:

1. [current/current-state.md](current/current-state.md)
2. one or more focused current documents:
   - [current/architecture.md](current/architecture.md)
   - [current/operations.md](current/operations.md)
   - [current/validation.md](current/validation.md)
   - [current/roadmap.md](current/roadmap.md)
3. historical documents only if current-layer context is not enough

## Practical Rule

Do not promote claims from `history`, `migration`, `archive`, or old notes back into `docs/current/*` unless newer code, tests, or runtime evidence confirms them.
