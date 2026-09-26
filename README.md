# confidential-balance-sync

Handling the `ApplyPendingBalance` race on Token-2022 confidential balances, for
custody and exchange integrations.

The race is cheap to detect locally and does not have to block a send.

## The problem

`ApplyPendingBalance` is computed by the client and unchecked by the program.
The client reads the account, decrypts the pending balance, and submits the sum
as a fresh AES ciphertext in `new_decryptable_available_balance`. On-chain the
program adds whatever is pending *at execution time* into `available_balance`
and stores the client's AES ciphertext verbatim.

A credit landing between the read and the transaction leaves the two
disagreeing. Nothing fails at apply time. The next spend is what fails, and an
attacker can hold an account in that state indefinitely with 1-unit transfers.

## The fix

`decryptable_available_balance` is a client-side cache. The token program holds
no AES key, so it cannot validate that field and never reads it, it only
overwrites it. What has to be correct is the plaintext balance passed into proof
generation, and that is recoverable from the ElGamal ciphertext.

Subtract the cached balance out of the on-chain `available_balance` and decrypt
the residual. Zero means in sync. Non-zero is the exact sum of credits the last
apply missed. The discrete log runs over the size of the discrepancy rather than
over the balance, so it resolves in milliseconds on an account of any size.

```rust
let residual = available_balance.subtract_amount(cached_balance);
let missed = elgamal_secret.decrypt_u32(&residual)?;  // 0 when in sync
let truth = cached_balance + missed;
```

When the residual is non-zero, pass proof generation an `AeCiphertext` built
locally over `truth` in place of the account's stored field.
`transfer_split_proof_data` and `withdraw_proof_data` both take that ciphertext
as a parameter. The proofs then agree with the on-chain ElGamal balance, the
transaction verifies, and the instruction writes a correct AES value back, so
the account resynchronizes on the spend with no repair transaction.

`spendable_balance` in `src/lib.rs` does both steps.

With this in place `ApplyPendingBalance` can run on any cadence, and inbound
dust costs one local subtraction per sweep.

## Symptom to watch for

A stale cache fails at proof generation rather than on-chain.
`transfer_split_proof_data` returns
`TokenProofGenerationError::ProofGeneration(InconsistentInput)` and nothing is
submitted, so no fee is burned. `TokenError::ConfidentialTransferBalanceMismatch`
is the on-chain error for the same condition, reached only by a client that
builds the instruction without the SDK consistency check.

## Two limits to build around

`decrypt_u32` resolves up to 2^32 - 1. A single confidential transfer can carry
up to 2^48 - 1, so one large missed transfer can put the residual out of range.
Fallbacks in order: test candidate sums against known expected inbound, then
replay the missed credits from `getSignaturesForAddress`. Replay is reliable
only for senders on the instruction-data proof flow, since the split-proof flow
holds the grouped ciphertext in a context state account that is usually closed
after the transfer.

`expected_pending_balance_credit_counter` and
`actual_pending_balance_credit_counter` give a cheaper detector, and the delta is
the exact number of missed credits. Both fields are overwritten by every apply,
so they describe the most recent apply rather than a specific one. A submit that
times out and gets retried, or two workers on one account, can leave them equal
over a balance that is still stale, and can leave `actual` below `expected`.
They hold under one-apply-in-flight-per-account discipline. `counter_gap` is
provided with that caveat, and both failures are reproduced in the tests.

Disabling confidential credits around a sweep also closes the window, at the
cost of rejecting legitimate inbound transfers for its duration.

## API

| Function | Purpose |
|---|---|
| `spendable_balance` | Real balance plus the `AeCiphertext` to feed proof generation |
| `check_sync` | Authoritative comparison against the on-chain ciphertext |
| `counter_gap` | Cheap pre-filter, single-writer only |
| `apply_instruction` | `ApplyPendingBalance` built from a given account state |
| `correction_instruction` | Standalone AES repair, rarely needed |
| `fence_close`, `fence_apply_and_open` | Disable/enable fenced sweep |

Everything takes raw account data plus keys and returns instructions. Nothing
sends a transaction, so it drops into a signing pipeline unchanged.

## Tests

```
cargo test
```

Nine tests, no validator required. Five cover the recovery arithmetic. Four run
the scenario against the real token-2022 program in LiteSVM:

- `stale_cache_is_detectable_recoverable_and_spendable` reproduces the race,
  confirms the spend on the cached balance is refused and the spend on the
  recovered balance is accepted while the stored field still disagrees.
- `stale_cache_does_not_block_a_confidential_transfer` does the same for a
  confidential transfer and checks the recipient is credited.
- `a_second_apply_erases_the_evidence_of_the_first` shows the counter check
  reporting a clean account that cannot be spent from.
- `actual_can_land_below_expected` produces `expected = 3, actual = 1`.

Verified against `spl-token-2022-interface` 3.1.2 and `solana-zk-sdk` 7.0.1.

## Note

One trap if you reassemble a pending balance from its lo and hi halves: do not
use `try_combine_lo_hi_u64` from
`spl-token-confidential-transfer-proof-generation`. It is deprecated and its
body adds `amount_hi` to itself instead of `amount_lo`. The crate marks it as
containing logical errors. `spl-token-client`'s own path does not use it.
