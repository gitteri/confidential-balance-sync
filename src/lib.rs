//! Keeping a confidential token account's AES view in sync with its on-chain
//! ElGamal balance, and closing the ApplyPendingBalance race.
//!
//! Everything here is pure: it takes raw account data plus the account's keys
//! and returns instructions. Nothing sends a transaction, so it drops into a
//! custody pipeline that signs and submits on its own.

use solana_address::Address;
use solana_instruction::Instruction;

use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalSecretKey},
};
use spl_token_2022_interface::{
    error::TokenError,
    extension::{
        confidential_transfer::{
            instruction::{
                apply_pending_balance, disable_confidential_credits,
                enable_confidential_credits,
            },
            ConfidentialTransferAccount, PENDING_BALANCE_LO_BIT_LENGTH,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::Account,
};

#[derive(Debug)]
pub enum SyncError {
    Extension(TokenError),
    Deserialize,
    AesDecrypt,
    /// The residual exceeded the 2^32 discrete-log window. Fall back to a
    /// bounded candidate search or to replaying history.
    ResidualOutOfRange { aes_view: u64 },
}

/// Result of comparing the AES view against the on-chain ElGamal balance.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncStatus {
    /// The two agree. `available` is spendable.
    InSync { available: u64 },
    /// An apply landed with a stale view. `truth` is the real available
    /// balance; write it back with `correction_instruction`.
    Stale {
        aes_view: u64,
        missed: u64,
        truth: u64,
    },
}

fn confidential_state<'a>(
    state: &'a StateWithExtensions<'a, Account>,
) -> Result<&'a ConfidentialTransferAccount, SyncError> {
    state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| SyncError::Extension(TokenError::ExtensionNotFound))
}

/// The authoritative check.
///
/// Subtracts the account's own AES number out of the on-chain ElGamal
/// `available_balance`. The residual encrypts exactly the sum of anything the
/// account received that its AES view never accounted for, so the discrete log
/// runs over the size of the discrepancy instead of over the whole balance.
///
/// This does not care how many `ApplyPendingBalance` instructions ran, or who
/// ran them. The credit counters cannot say that; they are overwritten by every
/// apply and only describe the most recent one.
pub fn check_sync(
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    aes_key: &AeKey,
) -> Result<SyncStatus, SyncError> {
    let state = StateWithExtensions::<Account>::unpack(account_data)
        .map_err(|_| SyncError::Deserialize)?;
    let ct = confidential_state(&state)?;

    let available: ElGamalCiphertext = ct
        .available_balance
        .try_into()
        .map_err(|_| SyncError::Deserialize)?;
    let decryptable: AeCiphertext = ct
        .decryptable_available_balance
        .try_into()
        .map_err(|_| SyncError::Deserialize)?;

    let aes_view = aes_key.decrypt(&decryptable).ok_or(SyncError::AesDecrypt)?;

    let residual = available.subtract_amount(aes_view);
    let missed = elgamal_secret
        .decrypt_u32(&residual)
        .ok_or(SyncError::ResidualOutOfRange { aes_view })?;

    Ok(if missed == 0 {
        SyncStatus::InSync {
            available: aes_view,
        }
    } else {
        SyncStatus::Stale {
            aes_view,
            missed,
            truth: aes_view
                .checked_add(missed)
                .ok_or(SyncError::ResidualOutOfRange { aes_view })?,
        }
    })
}

/// The cheap pre-filter.
///
/// `Some(n)` means the last apply missed `n` credits. `Some(0)` means the last
/// apply was clean. Only conclusive when one apply is in flight per account at
/// a time; a concurrent apply overwrites both counters and can report zero over
/// a balance an earlier apply already left stale. Treat this as a hint and
/// `check_sync` as the answer.
pub fn counter_gap(account_data: &[u8]) -> Result<u64, SyncError> {
    let state = StateWithExtensions::<Account>::unpack(account_data)
        .map_err(|_| SyncError::Deserialize)?;
    let ct = confidential_state(&state)?;

    let expected = u64::from(ct.expected_pending_balance_credit_counter);
    let actual = u64::from(ct.actual_pending_balance_credit_counter);
    // saturating: a concurrent apply can leave actual below expected
    Ok(actual.saturating_sub(expected))
}

/// Builds `ApplyPendingBalance` against the state you just read.
///
/// Returns the instruction and the available balance it will produce if nothing
/// credits the account before it lands. Check that prediction with `check_sync`
/// after the transaction confirms; do not assume it.
pub fn apply_instruction(
    token_program_id: &Address,
    account: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    aes_key: &AeKey,
) -> Result<(Instruction, u64), SyncError> {
    let state = StateWithExtensions::<Account>::unpack(account_data)
        .map_err(|_| SyncError::Deserialize)?;
    let ct = confidential_state(&state)?;

    let pending_lo: ElGamalCiphertext = ct
        .pending_balance_lo
        .try_into()
        .map_err(|_| SyncError::Deserialize)?;
    let pending_hi: ElGamalCiphertext = ct
        .pending_balance_hi
        .try_into()
        .map_err(|_| SyncError::Deserialize)?;
    let decryptable: AeCiphertext = ct
        .decryptable_available_balance
        .try_into()
        .map_err(|_| SyncError::Deserialize)?;

    let lo = elgamal_secret
        .decrypt_u32(&pending_lo)
        .ok_or(SyncError::ResidualOutOfRange { aes_view: 0 })?;
    let hi = elgamal_secret
        .decrypt_u32(&pending_hi)
        .ok_or(SyncError::ResidualOutOfRange { aes_view: 0 })?;

    // (hi << 16) + lo. Both operands came from decrypt_u32 so hi is at most
    // 2^32-1 and the shift cannot drop bits.
    //
    // Do not reach for try_combine_lo_hi_u64 in the proof-generation crate. It
    // is deprecated and adds amount_hi to itself instead of amount_lo.
    let pending = hi
        .checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
        .and_then(|shifted| shifted.checked_add(lo))
        .ok_or(SyncError::Deserialize)?;

    let current = aes_key.decrypt(&decryptable).ok_or(SyncError::AesDecrypt)?;
    let new_available = current.checked_add(pending).ok_or(SyncError::Deserialize)?;

    let expected_counter = u64::from(ct.pending_balance_credit_counter);
    let ix = apply_pending_balance(
        token_program_id,
        account,
        expected_counter,
        &aes_key.encrypt(new_available).into(),
        authority,
        multisig_signers,
    )
    .map_err(|_| SyncError::Deserialize)?;

    Ok((ix, new_available))
}

/// The fix. Returns the balance you can actually spend, plus the
/// `AeCiphertext` to hand to proof generation in place of the account's stored
/// `decryptable_available_balance`.
///
/// The token program holds no AES key, so it cannot and does not validate the
/// stored field. It only overwrites it. What has to be right is the plaintext
/// balance the client feeds into proof generation, and that is recoverable from
/// the ElGamal ciphertext whenever the cached field has gone stale.
///
/// So a stale AES view never has to block a send and never needs a repair
/// transaction first. Resolve the balance, build the transfer against it, and
/// the transfer writes a correct AES value back as a side effect.
///
/// Pass the returned ciphertext as `current_decryptable_available_balance` to
/// `transfer_split_proof_data`.
pub fn spendable_balance(
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    aes_key: &AeKey,
) -> Result<(u64, AeCiphertext), SyncError> {
    match check_sync(account_data, elgamal_secret, aes_key)? {
        // Cache agrees with the chain; reuse it as-is.
        SyncStatus::InSync { available } => Ok((available, aes_key.encrypt(available))),
        // Cache is behind. Build a ciphertext over the real balance instead.
        SyncStatus::Stale { truth, .. } => Ok((truth, aes_key.encrypt(truth))),
    }
}

/// Writes a corrected AES balance back as a standalone transaction.
///
/// Usually unnecessary. `spendable_balance` lets a stale cache heal on the next
/// transfer at no extra cost, so reach for this only when you want the stored
/// field correct without waiting for a send, for example so a monitoring system
/// reading the account sees the right number.
///
/// There is no dedicated instruction for it. `ApplyPendingBalance` has no guard
/// requiring a non-zero pending balance, so an apply with nothing pending is a
/// no-op on the ElGamal side and overwrites the AES ciphertext.
pub fn correction_instruction(
    token_program_id: &Address,
    account: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
    account_data: &[u8],
    truth: u64,
    aes_key: &AeKey,
) -> Result<Instruction, SyncError> {
    let state = StateWithExtensions::<Account>::unpack(account_data)
        .map_err(|_| SyncError::Deserialize)?;
    let ct = confidential_state(&state)?;

    apply_pending_balance(
        token_program_id,
        account,
        u64::from(ct.pending_balance_credit_counter),
        &aes_key.encrypt(truth).into(),
        authority,
        multisig_signers,
    )
    .map_err(|_| SyncError::Deserialize)
}

/// Step one of a fenced sweep: shut the account to inbound confidential credits
/// so the read that follows is stable.
///
/// Not the default, and not the answer to the race. While this is in force the
/// account rejects every inbound confidential transfer, including legitimate
/// deposits from people who have no idea the window is open, and the window is
/// two confirmed transactions wide. For a custody deposit address that trade is
/// almost always worse than the staleness it prevents, because `spendable_balance`
/// already makes staleness a non-event.
///
/// The one case that justifies it: the account routinely receives more than
/// 2^32 base units inside a single read-to-apply window, which puts the residual
/// past the discrete-log ceiling, and neither a bounded search against expected
/// deposits nor replaying history is available. Fencing makes that residual
/// impossible instead of merely usually small.
///
/// Send this and wait for confirmation before reading. Folding it into the same
/// transaction as the apply does nothing, because the race is between the read
/// and the apply, and that spans network time.
pub fn fence_close(
    token_program_id: &Address,
    account: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
) -> Result<Instruction, SyncError> {
    disable_confidential_credits(token_program_id, account, authority, multisig_signers)
        .map_err(|_| SyncError::Deserialize)
}

/// Step three: apply the exact pending balance and reopen the account, atomically.
pub fn fence_apply_and_open(
    token_program_id: &Address,
    account: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    aes_key: &AeKey,
) -> Result<(Vec<Instruction>, u64), SyncError> {
    let (apply, new_available) = apply_instruction(
        token_program_id,
        account,
        authority,
        multisig_signers,
        account_data,
        elgamal_secret,
        aes_key,
    )?;
    let open = enable_confidential_credits(token_program_id, account, authority, multisig_signers)
        .map_err(|_| SyncError::Deserialize)?;
    Ok((vec![apply, open], new_available))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_zk_sdk::encryption::elgamal::ElGamalKeypair;

    /// The claim the whole recovery path rests on: subtracting a known stale
    /// plaintext out of the on-chain ciphertext leaves a residual that decrypts
    /// over the size of the discrepancy, not over the balance.
    #[test]
    fn residual_recovers_exactly_the_missed_sum() {
        let keypair = ElGamalKeypair::new_rand();

        // On-chain truth after a stale apply swept in credits the client missed.
        let truth: u64 = 4_000_000_000_000;
        let stale: u64 = 3_999_999_999_997; // three 1-unit dust transfers raced
        let on_chain = keypair.pubkey().encrypt(truth);

        let residual = on_chain.subtract_amount(stale);
        let missed = keypair.secret().decrypt_u32(&residual).unwrap();

        assert_eq!(missed, 3);
        assert_eq!(stale + missed, truth);
    }

    /// A balance far outside the 2^32 discrete-log window still recovers,
    /// because the search runs over the gap and not over the balance.
    #[test]
    fn large_balance_small_gap_still_decodes() {
        let keypair = ElGamalKeypair::new_rand();
        let truth: u64 = u64::MAX / 2;
        let stale = truth - 1;

        let residual = keypair.pubkey().encrypt(truth).subtract_amount(stale);
        assert_eq!(keypair.secret().decrypt_u32(&residual).unwrap(), 1);
    }

    /// In-sync accounts produce a zero residual, which is the detector.
    #[test]
    fn zero_residual_means_in_sync() {
        let keypair = ElGamalKeypair::new_rand();
        let balance: u64 = 123_456_789;

        let residual = keypair.pubkey().encrypt(balance).subtract_amount(balance);
        assert_eq!(keypair.secret().decrypt_u32(&residual).unwrap(), 0);
    }

    /// Pins the lo/hi layout the apply path depends on, and the widest values
    /// decrypt_u32 can hand it.
    #[test]
    fn pending_combine_is_hi_shifted_plus_lo() {
        let combine = |lo: u64, hi: u64| {
            hi.checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
                .and_then(|s| s.checked_add(lo))
        };
        assert_eq!(combine(7, 1).unwrap(), (1u64 << 16) + 7);
        assert_eq!(combine(0, 0).unwrap(), 0);
        // widest inputs decrypt_u32 can produce still fit in u64
        let max = u32::MAX as u64;
        assert_eq!(combine(max, max).unwrap(), (max << 16) + max);
        // the widest pending balance the 32-bit decoder can ever reconstruct
        assert_eq!(combine(max, max).unwrap(), 281_479_271_612_415);
    }

    /// The documented ceiling: a gap at or above 2^32 is not decodable, and the
    /// caller has to fall through to a bounded search or to replaying history.
    #[test]
    fn gap_beyond_the_window_returns_none() {
        let keypair = ElGamalKeypair::new_rand();
        let truth: u64 = 1 << 33;

        let residual = keypair.pubkey().encrypt(truth).subtract_amount(0u64);
        assert!(keypair.secret().decrypt_u32(&residual).is_none());
    }
}
