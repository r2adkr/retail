# Local changes to boringtun 0.7.1

Vendored from crates.io `boringtun` 0.7.1 (BSD-3-Clause, see `LICENSE`) so
retaild can encrypt and decrypt one peer's transport packets on several cores.
Everything else is unchanged upstream code.

- `noise::Session` is re-exported and sessions are stored as `Arc<Session>`, so
  worker threads can use a session without holding the `Tunn`.
- `Session::reserve_counters`, `Session::encrypt_with_counter`,
  `Session::decrypt_data`: the per-packet crypto of `encapsulate` /
  `decapsulate`, usable concurrently (`&self`).
- `Tunn::current_send_session`, `Tunn::session_for`: look up a session.
- `Tunn::note_sent`, `Tunn::note_received`: the timer ticks, byte counters and
  session switch that `encapsulate` / `decapsulate` perform per packet, applied
  once per batch. Callers must call them for every batch they process outside
  `Tunn`, or keepalives and rekeying misbehave.
- `RateLimiter::verify_mac1`: checks only mac1, so retaild can reject forged
  handshake initiations before `parse_handshake_anon` spends a Diffie-Hellman
  on them (upstream runs that lookup only inside `decapsulate`, after mac1).
- `src/lib.rs`: `#![allow(...)]` for upstream warnings (no code change).
