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

That holds for applies that landed before the read. An apply that moves pending
credits into available between the read and the spend changes the source
ciphertext, and the program rejects the spend with
`ConfidentialTransferBalanceMismatch`. Re-read and rebuild, or run applies and
spends for an account on one worker.
`an_apply_between_read_and_send_fails_the_send` reproduces it.

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
Fallbacks in order: test candidate sums against known expected inbound with
`available_matches`, then replay the missed credits from
`getSignaturesForAddress`. Replay is reliable
only for senders on the instruction-data proof flow, since the split-proof flow
holds the grouped ciphertext in a context state account that is usually closed
after the transfer.

Testing a candidate means subtracting it and checking that the residual encrypts
zero. The residual keeps the original ciphertext's randomness, so it never
byte-matches a fresh encryption of zero. `encrypts_zero` decrypts with the
ElGamal secret and checks for the identity point instead.

The same ceiling applies to the pending balance before an apply. One credit's hi
half is at most 2^32 - 1 and always decodes, but two large credits can push
`pending_balance_hi` past it. Confirm the pending total from deposit records
with `pending_matches` and build the apply with `apply_with_balances`. With no
candidate to check, the amount has to come from off chain.

`expected_pending_balance_credit_counter` and
`actual_pending_balance_credit_counter` give a cheaper detector, and the delta is
the exact number of missed credits. Both fields are overwritten by every apply,
so they describe the most recent apply rather than a specific one. A submit that
times out and gets retried, or two workers on one account, can leave them equal
over a balance that is still stale, and can leave `actual` below `expected`.
They hold under one-apply-in-flight-per-account discipline. `counter_gap`
returns `Clean`, `Missed(n)` or `Inverted`, and anything but `Clean` needs
reconciling. Both failures are reproduced in the tests.

Disabling confidential credits around a sweep also closes the window, at the
cost of rejecting legitimate inbound transfers for its duration. Deposit,
confidential transfer and confidential mint all check that flag. Plain transfers
still land in the public `amount`, which the apply never reads.

## API

| Function | Purpose |
|---|---|
| `spendable_balance` | Real balance plus the `AeCiphertext` to feed proof generation |
| `check_sync` | Authoritative comparison against the on-chain ciphertext |
| `counter_gap` | Cheap pre-filter, single-writer only |
| `apply_instruction` | `ApplyPendingBalance` that writes true available plus pending, so it also repairs a stale cache |
| `apply_with_balances` | Same, from balances recovered off chain when a discrete log is out of range |
| `available_matches`, `pending_matches` | Confirm a candidate balance against the ciphertext |
| `encrypts_zero` | Zero check through the secret key |
| `fence_close`, `fence_apply_and_open` | Disable/enable fenced sweep |

Everything takes raw account data plus keys and returns instructions. Nothing
sends a transaction, so it drops into a signing pipeline unchanged.

## Tests

```
cargo test
```

Fourteen tests, no validator required. Six cover the recovery arithmetic. Eight
run against the real token-2022 program in LiteSVM:

- `stale_cache_is_detectable_recoverable_and_spendable` reproduces the race,
  confirms the spend on the cached balance is refused and the spend on the
  recovered balance is accepted while the stored field still disagrees.
- `stale_cache_does_not_block_a_confidential_transfer` does the same for a
  confidential transfer and checks the recipient is credited.
- `an_apply_between_read_and_send_fails_the_send` shows the spend failing on
  chain and a fresh read fixing it.
- `a_second_apply_erases_the_evidence_of_the_first` shows the counter check
  reporting a clean account that cannot be spent from.
- `actual_can_land_below_expected` produces `expected = 3, actual = 1`.
- `a_repair_has_to_include_pending` shows a repair that writes only the
  available balance leaving the account stale by the pending amount.
- `pending_past_the_window_is_confirmed_from_records` pushes
  `pending_balance_hi` past 2^32 and applies from a confirmed candidate.
- `the_fence_blocks_confidential_credits_only` checks Deposit is refused behind
  the fence while a plain transfer lands.

Verified against `spl-token-2022-interface` 3.1.2, `solana-zk-sdk` 7.0.1 and the
spl_token_2022 11.0.0 program bundled with LiteSVM 0.16.0. `solana-zk-sdk` 8.0.1
is out, but proof generation 0.6.1 still requires ^7.

## Note

One trap if you reassemble a pending balance from its lo and hi halves: do not
use `try_combine_lo_hi_u64` from
`spl-token-confidential-transfer-proof-generation`. It is deprecated and its
body adds `amount_hi` to itself instead of `amount_lo`. The crate marks it as
containing logical errors. `spl-token-client`'s own path does not use it.
