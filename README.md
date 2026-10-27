# vak-sandbox

A runtime-agnostic execution sandbox for safe agent code execution with reviewable promotion.

## Philosophy

Most sandboxes only do *process containment* (jail a command). vak-sandbox does both:

1. **Process containment** - OS-level isolation (macOS Seatbelt, Linux Landlock/seccomp/bubblewrap) to restrict what a process can access
2. **Realm isolation + reviewable promotion** - Give agents an isolated working copy to do anything (install deps, run tests, build), diff all changes, review them, then atomically promote with crash-safe journaling and rollback

This is inspired by [vak/code](https://github.com/nranjan2code/code)'s `vak-sandbox` (transactional promotion with receipts) and [Anthropic's sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) (process capability restriction), built fresh for Vakyartha's needs.

## Use Cases

- **MCP servers** - Jail third-party MCP processes with minimal filesystem/network access
- **Agent code execution** - Let agents run shell commands, edit files, install packages in isolation, review changes before applying to real workspace
- **Tool execution** - Safely run any build/test/lint commands
- **Any runtime needs** - Node, Python, Go, Rust, etc. - if it needs to execute code, sandbox it

## Architecture

- **Backend-agnostic** - Trait-based backends (Seatbelt, Landlock, Bubblewrap, Docker) with plugin system
- **Two modes** - `ProcessSandbox` for single-command jailing, `RealmSandbox` for full environment with promotion workflow
- **Crash-safe promotion** - Write-ahead journal, backups, atomic apply, rollback/undo
- **Deny-by-default** - Explicit allowlists only, symlink/traversal protection
- **Observable** - Full audit trail of creates/execs/promotes/undoes

## Status

Early development. macOS Seatbelt support first.
