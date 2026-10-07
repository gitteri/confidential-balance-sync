//! Keeping a confidential token account's AES view in sync with its on-chain
//! ElGamal balance, and closing the ApplyPendingBalance race.
//!
//! Everything here is pure: it takes raw account data plus the account's keys
//! and returns instructions. Nothing sends a transaction, so it drops into a
//! custody pipeline that signs and submits on its own.

use curve25519_dalek::traits::IsIdentity;
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
    Overflow,
    /// The residual exceeded the 2^32 discrete-log window. Confirm a candidate
    /// with `available_matches`.
    ResidualOutOfRange { aes_view: u64 },
    /// `pending_balance_hi` exceeded the 2^32 discrete-log window. Confirm a
    /// candidate with `pending_matches`.
    PendingOutOfRange,
    /// A supplied balance does not match the on-chain ciphertext.
    CandidateMismatch,
}

/// Result of comparing the AES view against the on-chain ElGamal balance.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncStatus {
    /// The two agree. `available` is spendable.
    InSync { available: u64 },
    /// An apply landed with a stale view. `truth` is the real available
    /// balance; `spendable_balance` spends against it and `apply_instruction`
    /// writes it back.
    Stale {
        aes_view: u64,
        missed: u64,
        truth: u64,
    },
}

/// What the credit counters say about the most recent apply.
#[derive(Debug, PartialEq, Eq)]
pub enum CounterGap {
    /// The counters match. Conclusive only with one apply in flight per account.
    Clean,
    /// The last apply swept in this many credits its client never read.
    Missed(u64),
    /// The last apply carried a counter read before another apply reset it.
    Inverted { expected: u64, actual: u64 },
}

fn confidential_state<'a>(
    state: &'a StateWithExtensions<'a, Account>,
) -> Result<&'a ConfidentialTransferAccount, SyncError> {
    state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| SyncError::Extension(TokenError::ExtensionNotFound))
}

fn ciphertexts(
    account_data: &[u8],
) -> Result<(ElGamalCiphertext, ElGamalCiphertext, AeCiphertext, u64), SyncError> {
    let state = StateWithExtensions::<Account>::unpack(account_data)
        .map_err(|_| SyncError::Deserialize)?;
    let ct = confidential_state(&state)?;

    let available: ElGamalCiphertext = ct
        .available_balance
        .try_into()
        .map_err(|_| SyncError::Deserialize)?;
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

    let pending = pending_lo + pending_hi * (1u64 << PENDING_BALANCE_LO_BIT_LENGTH);
    Ok((
        available,
        pending,
        decryptable,
        u64::from(ct.pending_balance_credit_counter),
    ))
}

/// True if `ciphertext` encrypts zero under `secret`, whatever its randomness.
pub fn encrypts_zero(secret: &ElGamalSecretKey, ciphertext: &ElGamalCiphertext) -> bool {
    secret.decrypt(ciphertext).target.is_identity()
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
    let (available, _, decryptable, _) = ciphertexts(account_data)?;
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
            truth: aes_view.checked_add(missed).ok_or(SyncError::Overflow)?,
        }
    })
}

/// Confirms a candidate available balance, for when `check_sync` returns
/// `ResidualOutOfRange`. One subtraction and one scalar multiplication.
pub fn available_matches(
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    candidate: u64,
) -> Result<bool, SyncError> {
    let (available, _, _, _) = ciphertexts(account_data)?;
    Ok(encrypts_zero(
        elgamal_secret,
        &available.subtract_amount(candidate),
    ))
}

/// Confirms a candidate pending balance, for when `pending_balance_hi` is past
/// the discrete-log window. Check it before applying, while pending is still
/// separate from available.
pub fn pending_matches(
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    candidate: u64,
) -> Result<bool, SyncError> {
    let (_, pending, _, _) = ciphertexts(account_data)?;
    Ok(encrypts_zero(elgamal_secret, &pending.subtract_amount(candidate)))
}

/// The cheap pre-filter.
///
/// Reconcile on anything but `Clean`. `Clean` is only conclusive with one apply in flight per account.
pub fn counter_gap(account_data: &[u8]) -> Result<CounterGap, SyncError> {
    let state = StateWithExtensions::<Account>::unpack(account_data)
        .map_err(|_| SyncError::Deserialize)?;
    let ct = confidential_state(&state)?;

    let expected = u64::from(ct.expected_pending_balance_credit_counter);
    let actual = u64::from(ct.actual_pending_balance_credit_counter);
    Ok(match actual.checked_sub(expected) {
        Some(0) => CounterGap::Clean,
        Some(missed) => CounterGap::Missed(missed),
        None => CounterGap::Inverted { expected, actual },
    })
}

/// Builds `ApplyPendingBalance` against the state you just read.
///
/// Writes true available plus pending to the AES balance, so every apply also repairs a stale cache.
/// Returns the instruction and the expected resulting balance; confirm it with `check_sync`.
pub fn apply_instruction(
    token_program_id: &Address,
    account: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    aes_key: &AeKey,
) -> Result<(Instruction, u64), SyncError> {
    let (available, _) = spendable_balance(account_data, elgamal_secret, aes_key)?;
    let pending = decrypt_pending(account_data, elgamal_secret)?;
    build_apply(
        token_program_id,
        account,
        authority,
        multisig_signers,
        account_data,
        aes_key,
        available,
        pending,
    )
}

/// `apply_instruction` for balances recovered elsewhere (deposit records,
/// history) when a discrete log is out of range. Both are checked against the
/// ciphertexts first.
#[allow(clippy::too_many_arguments)]
pub fn apply_with_balances(
    token_program_id: &Address,
    account: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    aes_key: &AeKey,
    available: u64,
    pending: u64,
) -> Result<(Instruction, u64), SyncError> {
    if !available_matches(account_data, elgamal_secret, available)?
        || !pending_matches(account_data, elgamal_secret, pending)?
    {
        return Err(SyncError::CandidateMismatch);
    }
    build_apply(
        token_program_id,
        account,
        authority,
        multisig_signers,
        account_data,
        aes_key,
        available,
        pending,
    )
}

fn decrypt_pending(account_data: &[u8], elgamal_secret: &ElGamalSecretKey) -> Result<u64, SyncError> {
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

    let lo = elgamal_secret
        .decrypt_u32(&pending_lo)
        .ok_or(SyncError::PendingOutOfRange)?;
    let hi = elgamal_secret
        .decrypt_u32(&pending_hi)
        .ok_or(SyncError::PendingOutOfRange)?;

    // try_combine_lo_hi_u64 in proof-generation is buggy (adds hi to itself).
    hi.checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
        .and_then(|shifted| shifted.checked_add(lo))
        .ok_or(SyncError::Overflow)
}

#[allow(clippy::too_many_arguments)]
fn build_apply(
    token_program_id: &Address,
    account: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
    account_data: &[u8],
    aes_key: &AeKey,
    available: u64,
    pending: u64,
) -> Result<(Instruction, u64), SyncError> {
    let (_, _, _, expected_counter) = ciphertexts(account_data)?;
    let new_available = available.checked_add(pending).ok_or(SyncError::Overflow)?;
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
/// Only as fresh as `account_data`: an apply landing first fails the spend, so re-read and rebuild.
///
/// Pass the returned ciphertext as `current_decryptable_available_balance` to
/// `transfer_split_proof_data`.
pub fn spendable_balance(
    account_data: &[u8],
    elgamal_secret: &ElGamalSecretKey,
    aes_key: &AeKey,
) -> Result<(u64, AeCiphertext), SyncError> {
    let available = match check_sync(account_data, elgamal_secret, aes_key)? {
        SyncStatus::InSync { available } => available,
        SyncStatus::Stale { truth, .. } => truth,
    };
    Ok((available, aes_key.encrypt(available)))
}

/// Step one of a fenced sweep: shut the account to inbound confidential credits
/// so the read that follows is stable.
///
/// Blocks every credit to the confidential balances. Plain transfers still land in the public `amount`.
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
/// past the discrete-log ceiling, and neither a candidate check against expected
/// deposits nor replaying history is available.
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

    /// A residual keeps the ciphertext's randomness, so it never equals a fresh
    /// zero ciphertext; the zero check has to go through the secret key.
    #[test]
    fn candidate_check_needs_the_secret_not_byte_equality() {
        let keypair = ElGamalKeypair::new_rand();
        let balance: u64 = 1 << 40;
        let residual = keypair.pubkey().encrypt(balance).subtract_amount(balance);

        assert_ne!(residual, keypair.pubkey().encrypt(0u64));
        assert_ne!(residual, ElGamalCiphertext::default());
        assert!(encrypts_zero(keypair.secret(), &residual));

        let wrong = keypair.pubkey().encrypt(balance).subtract_amount(balance - 1);
        assert!(!encrypts_zero(keypair.secret(), &wrong));
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
