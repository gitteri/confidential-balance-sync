use confidential_balance_sync::{
    apply_instruction, apply_with_balances, check_sync, counter_gap, fence_apply_and_open,
    fence_close, pending_matches, spendable_balance, CounterGap, SyncError, SyncStatus,
};
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use solana_zk_sdk::{
    encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        elgamal::ElGamalKeypair,
    },
    zk_elgamal_proof_program::{
        errors::ProofGenerationError, pubkey_validity::build_pubkey_validity_proof_data,
    },
};
use spl_token_2022_interface::{
    error::TokenError,
    extension::{
        confidential_transfer::{instruction as ct_ix, ConfidentialTransferAccount},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction as token_ix,
    state::{Account, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::{
    errors::TokenProofGenerationError, transfer::transfer_split_proof_data,
    withdraw::withdraw_proof_data,
};

const T22: Address = spl_token_2022_interface::ID;
const DECIMALS: u8 = 6;

/// Where a spend was stopped: by the SDK before submission, or by the program.
#[derive(Debug)]
enum SpendError {
    Proof(TokenProofGenerationError),
    Tx(TransactionError),
}

fn assert_refused_before_submission(result: Result<(), SpendError>) {
    assert!(
        matches!(
            result,
            Err(SpendError::Proof(TokenProofGenerationError::ProofGeneration(
                ProofGenerationError::InconsistentInput
            )))
        ),
        "expected InconsistentInput from proof generation, got {result:?}"
    );
}

fn assert_rejected_on_chain(result: Result<(), SpendError>, expected: TokenError) {
    match result {
        Err(SpendError::Tx(err)) => assert_token_error(Err(err), expected),
        other => panic!("expected {expected:?} from the program, got {other:?}"),
    }
}

fn assert_token_error(result: Result<(), TransactionError>, expected: TokenError) {
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(expected as u32)
        ))
    );
}

struct Env {
    svm: LiteSVM,
    payer: Keypair,
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        Self { svm, payer }
    }

    fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> Result<(), TransactionError> {
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new_signed_with_payer(
            ixs,
            Some(&self.payer.pubkey()),
            &signers,
            self.svm.latest_blockhash(),
        );
        let result = self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err);
        self.svm.expire_blockhash();
        result
    }

    fn account_data(&self, addr: &Address) -> Vec<u8> {
        self.svm.get_account(addr).unwrap().data
    }
}

/// Holds a confidential token account and its keys.
struct CtAccount {
    keypair: Keypair,
    owner: Keypair,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

impl CtAccount {
    fn address(&self) -> Address {
        self.keypair.pubkey()
    }
}

fn create_mint(env: &mut Env, mint: &Keypair) {
    let len =
        ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::ConfidentialTransferMint])
            .unwrap();
    let rent = env.svm.minimum_balance_for_rent_exemption(len);
    let ixs = vec![
        solana_system_interface::instruction::create_account(
            &env.payer.pubkey(),
            &mint.pubkey(),
            rent,
            len as u64,
            &T22,
        ),
        ct_ix::initialize_mint(&T22, &mint.pubkey(), Some(env.payer.pubkey()), true, None).unwrap(),
        token_ix::initialize_mint2(&T22, &mint.pubkey(), &env.payer.pubkey(), None, DECIMALS)
            .unwrap(),
    ];
    env.send(&ixs, &[mint]).expect("create mint");
}

fn create_ct_account(env: &mut Env, mint: &Address) -> CtAccount {
    let keypair = Keypair::new();
    let owner = Keypair::new();
    let elgamal = ElGamalKeypair::new_rand();
    let aes = AeKey::new_rand();

    let len = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .unwrap();
    let rent = env.svm.minimum_balance_for_rent_exemption(len);

    env.send(
        &[
            solana_system_interface::instruction::create_account(
                &env.payer.pubkey(),
                &keypair.pubkey(),
                rent,
                len as u64,
                &T22,
            ),
            token_ix::initialize_account3(&T22, &keypair.pubkey(), mint, &owner.pubkey()).unwrap(),
        ],
        &[&keypair],
    )
    .expect("create token account");

    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ixs = ct_ix::configure_account(
        &T22,
        &keypair.pubkey(),
        mint,
        &aes.encrypt(0).into(),
        u16::MAX as u64,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof),
    )
    .unwrap();
    env.send(&ixs, &[&owner]).expect("configure account");

    CtAccount {
        keypair,
        owner,
        elgamal,
        aes,
    }
}

fn mint_to(env: &mut Env, mint: &Address, acct: &CtAccount, amount: u64) {
    let ix = token_ix::mint_to(&T22, mint, &acct.address(), &env.payer.pubkey(), &[], amount)
        .unwrap();
    env.send(&[ix], &[]).expect("mint_to");
}

/// A mint and an account holding `balance` in its confidential available
/// balance, in sync, with 1_000_000 more in its public balance.
fn funded(env: &mut Env, mint: &Address, balance: u64) -> CtAccount {
    let acct = create_ct_account(env, mint);
    mint_to(env, mint, &acct, balance + 1_000_000);
    deposit(env, &acct, mint, balance).expect("deposit");
    let v = view(env, &acct);
    apply_from_snapshot(env, &acct, v.pending_counter, v.aes_balance + v.pending).unwrap();
    acct
}

/// Full confidential-transfer view of an account.
struct CtView {
    pending_counter: u64,
    aes_balance: u64,
    pending: u64,
}

fn view(env: &Env, acct: &CtAccount) -> CtView {
    let data = env.account_data(&acct.address());
    let state = StateWithExtensions::<Account>::unpack(&data).unwrap();
    let ct = state.get_extension::<ConfidentialTransferAccount>().unwrap();
    let secret = acct.elgamal.secret();
    let lo = secret
        .decrypt_u32(&ct.pending_balance_lo.try_into().unwrap())
        .unwrap();
    let hi = secret
        .decrypt_u32(&ct.pending_balance_hi.try_into().unwrap())
        .unwrap();
    CtView {
        pending_counter: u64::from(ct.pending_balance_credit_counter),
        aes_balance: acct
            .aes
            .decrypt(&ct.decryptable_available_balance.try_into().unwrap())
            .unwrap(),
        pending: (hi << 16) + lo,
    }
}

fn public_amount(env: &Env, acct: &CtAccount) -> u64 {
    let data = env.account_data(&acct.address());
    StateWithExtensions::<Account>::unpack(&data)
        .unwrap()
        .base
        .amount
}

fn deposit(
    env: &mut Env,
    acct: &CtAccount,
    mint: &Address,
    amount: u64,
) -> Result<(), TransactionError> {
    let ix = ct_ix::deposit(
        &T22,
        &acct.address(),
        mint,
        amount,
        DECIMALS,
        &acct.owner.pubkey(),
        &[],
    )
    .unwrap();
    env.send(&[ix], &[&acct.owner])
}

/// Builds ApplyPendingBalance from a snapshot taken at some earlier point.
/// Passing a stale snapshot is exactly what a racing client does.
fn apply_from_snapshot(
    env: &mut Env,
    acct: &CtAccount,
    expected_counter: u64,
    new_balance: u64,
) -> Result<(), TransactionError> {
    let ix = ct_ix::apply_pending_balance(
        &T22,
        &acct.address(),
        expected_counter,
        &acct.aes.encrypt(new_balance).into(),
        &acct.owner.pubkey(),
        &[],
    )
    .unwrap();
    env.send(&[ix], &[&acct.owner])
}

fn library_apply(env: &mut Env, acct: &CtAccount) -> u64 {
    let data = env.account_data(&acct.address());
    let (ix, new_available) = apply_instruction(
        &T22,
        &acct.address(),
        &acct.owner.pubkey(),
        &[],
        &data,
        acct.elgamal.secret(),
        &acct.aes,
    )
    .unwrap();
    env.send(&[ix], &[&acct.owner]).expect("apply");
    new_available
}

fn sync_status(env: &Env, acct: &CtAccount) -> SyncStatus {
    let data = env.account_data(&acct.address());
    check_sync(&data, acct.elgamal.secret(), &acct.aes).unwrap()
}

/// Builds a withdraw from `data`, using `claimed_balance` as the client's idea
/// of what it holds. Pass the stale cached number and the proofs describe a
/// balance the chain does not agree with.
fn build_withdraw(
    acct: &CtAccount,
    mint: &Address,
    data: &[u8],
    claimed_balance: u64,
    amount: u64,
) -> Result<Vec<Instruction>, TokenProofGenerationError> {
    let state = StateWithExtensions::<Account>::unpack(data).unwrap();
    let ct = state.get_extension::<ConfidentialTransferAccount>().unwrap();
    let proofs = withdraw_proof_data(
        &ct.available_balance.try_into().unwrap(),
        claimed_balance,
        amount,
        &acct.elgamal,
    )?;

    Ok(ct_ix::withdraw(
        &T22,
        &acct.address(),
        mint,
        amount,
        DECIMALS,
        &acct.aes.encrypt(claimed_balance - amount).into(),
        &acct.owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(1.try_into().unwrap(), &proofs.equality_proof_data),
        ProofLocation::InstructionOffset(2.try_into().unwrap(), &proofs.range_proof_data),
    )
    .unwrap())
}

fn try_withdraw(
    env: &mut Env,
    acct: &CtAccount,
    mint: &Address,
    claimed_balance: u64,
    amount: u64,
) -> Result<(), SpendError> {
    let data = env.account_data(&acct.address());
    let ixs =
        build_withdraw(acct, mint, &data, claimed_balance, amount).map_err(SpendError::Proof)?;
    env.send(&ixs, &[&acct.owner]).map_err(SpendError::Tx)
}

/// Builds a confidential transfer from `data`, where `claimed` is the AES
/// ciphertext the client feeds proof generation as its current balance.
#[allow(clippy::too_many_arguments)]
fn build_transfer(
    src: &CtAccount,
    dst: &CtAccount,
    mint: &Address,
    data: &[u8],
    claimed: &AeCiphertext,
    claimed_plain: u64,
    amount: u64,
) -> Result<Vec<Instruction>, TokenProofGenerationError> {
    let state = StateWithExtensions::<Account>::unpack(data).unwrap();
    let ct = state.get_extension::<ConfidentialTransferAccount>().unwrap();
    let proofs = transfer_split_proof_data(
        &ct.available_balance.try_into().unwrap(),
        claimed,
        amount,
        &src.elgamal,
        &src.aes,
        dst.elgamal.pubkey(),
        None,
    )?;

    Ok(ct_ix::transfer(
        &T22,
        &src.address(),
        mint,
        &dst.address(),
        &src.aes.encrypt(claimed_plain - amount).into(),
        &proofs.ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        &proofs.ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        &src.owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(1.try_into().unwrap(), &proofs.equality_proof_data),
        ProofLocation::InstructionOffset(
            2.try_into().unwrap(),
            &proofs.ciphertext_validity_proof_data_with_ciphertext.proof_data,
        ),
        ProofLocation::InstructionOffset(3.try_into().unwrap(), &proofs.range_proof_data),
    )
    .unwrap())
}

fn try_transfer(
    env: &mut Env,
    src: &CtAccount,
    dst: &CtAccount,
    mint: &Address,
    claimed: &AeCiphertext,
    claimed_plain: u64,
    amount: u64,
) -> Result<(), SpendError> {
    let data = env.account_data(&src.address());
    let ixs = build_transfer(src, dst, mint, &data, claimed, claimed_plain, amount)
        .map_err(SpendError::Proof)?;
    env.send(&ixs, &[&src.owner]).map_err(SpendError::Tx)
}

fn stored_decryptable(env: &Env, acct: &CtAccount) -> AeCiphertext {
    let data = env.account_data(&acct.address());
    let state = StateWithExtensions::<Account>::unpack(&data).unwrap();
    state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
        .decryptable_available_balance
        .try_into()
        .unwrap()
}

/// Lands the race: snapshot, credits arrive, the apply built from the snapshot
/// goes through.
fn race(env: &mut Env, acct: &CtAccount, mint: &Address, dust: &[u64]) {
    let snapshot = view(env, acct);
    for &amount in dust {
        deposit(env, acct, mint, amount).expect("deposit");
    }
    apply_from_snapshot(
        env,
        acct,
        snapshot.pending_counter,
        snapshot.aes_balance + snapshot.pending,
    )
    .unwrap();
}

/// Reproduces the ApplyPendingBalance race against the real token-2022 program,
/// then shows that the recovered balance is spendable while the cached one is not.
#[test]
fn stale_cache_is_detectable_recoverable_and_spendable() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = funded(&mut env, &mint.pubkey(), 1_000_000);

    let data = env.account_data(&alice.address());
    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::InSync {
            available: 1_000_000
        }
    );
    assert_eq!(counter_gap(&data).unwrap(), CounterGap::Clean);

    race(&mut env, &alice, &mint.pubkey(), &[1, 2, 3]);

    let data = env.account_data(&alice.address());
    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::Stale {
            aes_view: 1_000_000,
            missed: 6,
            truth: 1_000_006,
        }
    );
    assert_eq!(counter_gap(&data).unwrap(), CounterGap::Missed(3));

    assert_refused_before_submission(try_withdraw(
        &mut env,
        &alice,
        &mint.pubkey(),
        1_000_000,
        100,
    ));

    let (truth, _) = spendable_balance(&data, alice.elgamal.secret(), &alice.aes).unwrap();
    assert_eq!(truth, 1_000_006);
    try_withdraw(&mut env, &alice, &mint.pubkey(), truth, 100).expect("recovered balance spendable");

    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::InSync {
            available: 1_000_006 - 100
        }
    );
}

/// The same, for a real confidential transfer rather than a withdraw, using the
/// AeCiphertext that `spendable_balance` hands back.
#[test]
fn stale_cache_does_not_block_a_confidential_transfer() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = funded(&mut env, &mint.pubkey(), 1_000_000);
    let bob = create_ct_account(&mut env, &mint.pubkey());

    race(&mut env, &alice, &mint.pubkey(), &[7, 11]);

    let data = env.account_data(&alice.address());
    let stored = stored_decryptable(&env, &alice);
    assert_eq!(counter_gap(&data).unwrap(), CounterGap::Missed(2));

    assert_refused_before_submission(try_transfer(
        &mut env,
        &alice,
        &bob,
        &mint.pubkey(),
        &stored,
        1_000_000,
        500,
    ));

    let (truth, corrected) =
        spendable_balance(&data, alice.elgamal.secret(), &alice.aes).unwrap();
    assert_eq!(truth, 1_000_018);
    try_transfer(&mut env, &alice, &bob, &mint.pubkey(), &corrected, truth, 500)
        .expect("corrected transfer accepted");

    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::InSync {
            available: 1_000_018 - 500
        }
    );
    assert_eq!(view(&env, &bob).pending, 500, "recipient credited");
}

/// A spend is built against one read. An apply that moves pending credits into
/// available before it lands changes the source ciphertext, and the program
/// rejects the spend. A fresh read fixes it.
#[test]
fn an_apply_between_read_and_send_fails_the_send() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = funded(&mut env, &mint.pubkey(), 1_000_000);
    let bob = create_ct_account(&mut env, &mint.pubkey());

    let data = env.account_data(&alice.address());
    let (truth, corrected) =
        spendable_balance(&data, alice.elgamal.secret(), &alice.aes).unwrap();
    let ixs = build_transfer(&alice, &bob, &mint.pubkey(), &data, &corrected, truth, 500).unwrap();

    deposit(&mut env, &alice, &mint.pubkey(), 5).expect("deposit");
    library_apply(&mut env, &alice);

    assert_rejected_on_chain(
        env.send(&ixs, &[&alice.owner]).map_err(SpendError::Tx),
        TokenError::ConfidentialTransferBalanceMismatch,
    );

    let data = env.account_data(&alice.address());
    let (truth, corrected) =
        spendable_balance(&data, alice.elgamal.secret(), &alice.aes).unwrap();
    assert_eq!(truth, 1_000_005);
    try_transfer(&mut env, &alice, &bob, &mint.pubkey(), &corrected, truth, 500)
        .expect("rebuilt from a fresh read");
}

/// The counter check can report a clean account that is not clean.
///
/// Both counters are account state and every apply overwrites them. A second
/// apply that was itself in sync records equal counters over a balance the
/// first apply already left stale. A timed-out submit and its retry produce
/// this as readily as two workers do.
#[test]
fn a_second_apply_erases_the_evidence_of_the_first() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = funded(&mut env, &mint.pubkey(), 1_000_000);

    race(&mut env, &alice, &mint.pubkey(), &[9]);

    let data = env.account_data(&alice.address());
    assert_eq!(counter_gap(&data).unwrap(), CounterGap::Missed(1));
    assert!(matches!(
        sync_status(&env, &alice),
        SyncStatus::Stale { missed: 9, .. }
    ));

    // Worker 2 reads the stale cache, adds a pending balance of zero, and lands
    // cleanly against the counter it read.
    let v2 = view(&env, &alice);
    apply_from_snapshot(&mut env, &alice, v2.pending_counter, v2.aes_balance + v2.pending).unwrap();

    let data = env.account_data(&alice.address());
    assert_eq!(
        counter_gap(&data).unwrap(),
        CounterGap::Clean,
        "the second apply overwrote the evidence"
    );
    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::Stale {
            aes_view: 1_000_000,
            missed: 9,
            truth: 1_000_009,
        },
        "the ciphertext check still sees it"
    );

    assert_refused_before_submission(try_withdraw(
        &mut env,
        &alice,
        &mint.pubkey(),
        1_000_000,
        100,
    ));
}

/// `actual` can land below `expected`. A client reads the counter, someone
/// else's apply resets it to zero, a credit lands, and then the first client's
/// apply arrives carrying the old high value.
#[test]
fn actual_can_land_below_expected() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = create_ct_account(&mut env, &mint.pubkey());
    mint_to(&mut env, &mint.pubkey(), &alice, 2_000_000);

    for amount in [100u64, 200, 300] {
        deposit(&mut env, &alice, &mint.pubkey(), amount).expect("deposit");
    }
    let stale_snapshot = view(&env, &alice);
    assert_eq!(stale_snapshot.pending_counter, 3);

    apply_from_snapshot(
        &mut env,
        &alice,
        stale_snapshot.pending_counter,
        stale_snapshot.aes_balance + stale_snapshot.pending,
    )
    .unwrap();

    deposit(&mut env, &alice, &mint.pubkey(), 50).expect("deposit");

    let v = view(&env, &alice);
    apply_from_snapshot(&mut env, &alice, 3, v.aes_balance + v.pending).unwrap();

    let data = env.account_data(&alice.address());
    assert_eq!(
        counter_gap(&data).unwrap(),
        CounterGap::Inverted {
            expected: 3,
            actual: 1
        },
        "reported, not saturated to Clean"
    );
}

/// A repair apply writes the AES side, but the program also adds whatever is
/// pending to the ElGamal side in the same step. Writing only the corrected
/// available balance while credits are pending leaves the account stale by
/// exactly that pending amount. `apply_instruction` writes available plus
/// pending.
#[test]
fn a_repair_has_to_include_pending() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = funded(&mut env, &mint.pubkey(), 1_000_000);

    race(&mut env, &alice, &mint.pubkey(), &[1, 2, 3]);
    deposit(&mut env, &alice, &mint.pubkey(), 25).expect("deposit");

    let data = env.account_data(&alice.address());
    let (truth, _) = spendable_balance(&data, alice.elgamal.secret(), &alice.aes).unwrap();
    let counter = view(&env, &alice).pending_counter;
    apply_from_snapshot(&mut env, &alice, counter, truth).unwrap();
    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::Stale {
            aes_view: 1_000_006,
            missed: 25,
            truth: 1_000_031,
        },
        "writing truth alone recreated the mismatch"
    );

    deposit(&mut env, &alice, &mint.pubkey(), 40).expect("deposit");
    let predicted = library_apply(&mut env, &alice);
    assert_eq!(predicted, 1_000_071);
    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::InSync {
            available: 1_000_071
        }
    );
    let data = env.account_data(&alice.address());
    assert_eq!(counter_gap(&data).unwrap(), CounterGap::Clean);
}

/// Two maximum-size credits put `pending_balance_hi` past 2^32. The pending
/// total is still confirmable from the custodian's own records without a
/// discrete log, and the apply can be built from it.
#[test]
fn pending_past_the_window_is_confirmed_from_records() {
    const MAX_CREDIT: u64 = (1 << 48) - 1;

    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = create_ct_account(&mut env, &mint.pubkey());
    mint_to(&mut env, &mint.pubkey(), &alice, 2 * MAX_CREDIT);
    deposit(&mut env, &alice, &mint.pubkey(), MAX_CREDIT).expect("deposit");
    deposit(&mut env, &alice, &mint.pubkey(), MAX_CREDIT).expect("deposit");

    let data = env.account_data(&alice.address());
    let secret = alice.elgamal.secret();
    let address = alice.address();
    let owner = alice.owner.pubkey();

    assert!(matches!(
        apply_instruction(&T22, &address, &owner, &[], &data, secret, &alice.aes),
        Err(SyncError::PendingOutOfRange)
    ));

    let expected_pending = 2 * MAX_CREDIT;
    assert!(!pending_matches(&data, secret, expected_pending - 1).unwrap());
    assert!(pending_matches(&data, secret, expected_pending).unwrap());
    assert!(matches!(
        apply_with_balances(
            &T22, &address, &owner, &[], &data, secret, &alice.aes, 0, expected_pending - 1
        ),
        Err(SyncError::CandidateMismatch)
    ));

    let (ix, new_available) = apply_with_balances(
        &T22, &address, &owner, &[], &data, secret, &alice.aes, 0, expected_pending,
    )
    .unwrap();
    env.send(&[ix], &[&alice.owner]).expect("apply");

    assert_eq!(new_available, expected_pending);
    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::InSync {
            available: expected_pending
        }
    );
}

/// DisableConfidentialCredits stops every credit to the confidential balance.
/// Plain token transfers still land, in the public amount, which the apply
/// never reads.
#[test]
fn the_fence_blocks_confidential_credits_only() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = funded(&mut env, &mint.pubkey(), 1_000_000);
    let bob = funded(&mut env, &mint.pubkey(), 1_000_000);

    let ix = fence_close(&T22, &alice.address(), &alice.owner.pubkey(), &[]).unwrap();
    env.send(&[ix], &[&alice.owner]).expect("fence");

    assert_token_error(
        deposit(&mut env, &alice, &mint.pubkey(), 10),
        TokenError::ConfidentialTransferDepositsAndTransfersDisabled,
    );

    let bob_data = env.account_data(&bob.address());
    let (bob_balance, bob_ct) =
        spendable_balance(&bob_data, bob.elgamal.secret(), &bob.aes).unwrap();
    let ixs = build_transfer(&bob, &alice, &mint.pubkey(), &bob_data, &bob_ct, bob_balance, 10)
        .unwrap();
    assert_token_error(
        env.send(&ixs, &[&bob.owner]),
        TokenError::ConfidentialTransferDepositsAndTransfersDisabled,
    );

    let public_before = public_amount(&env, &alice);
    let ix = token_ix::transfer_checked(
        &T22,
        &bob.address(),
        &mint.pubkey(),
        &alice.address(),
        &bob.owner.pubkey(),
        &[],
        10,
        DECIMALS,
    )
    .unwrap();
    env.send(&[ix], &[&bob.owner]).expect("plain transfer");
    assert_eq!(public_amount(&env, &alice), public_before + 10);
    assert_eq!(view(&env, &alice).pending_counter, 0);

    let data = env.account_data(&alice.address());
    let (ixs, new_available) = fence_apply_and_open(
        &T22,
        &alice.address(),
        &alice.owner.pubkey(),
        &[],
        &data,
        alice.elgamal.secret(),
        &alice.aes,
    )
    .unwrap();
    env.send(&ixs, &[&alice.owner]).expect("apply and reopen");
    assert_eq!(
        sync_status(&env, &alice),
        SyncStatus::InSync {
            available: new_available
        }
    );
    deposit(&mut env, &alice, &mint.pubkey(), 10).expect("open again");
}
