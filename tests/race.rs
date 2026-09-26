use confidential_balance_sync::{check_sync, counter_gap, spendable_balance, SyncStatus};
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_zk_sdk::{
    encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use spl_token_2022_interface::{
    extension::{
        confidential_transfer::{
            instruction as ct_ix,
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction as token_ix,
    state::{Account, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::{
    transfer::transfer_split_proof_data, withdraw::withdraw_proof_data,
};
use solana_zk_sdk::encryption::auth_encryption::AeCiphertext;

const T22: Address = spl_token_2022_interface::ID;
const DECIMALS: u8 = 6;

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

    fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> Result<(), String> {
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new_signed_with_payer(
            ixs,
            Some(&self.payer.pubkey()),
            &signers,
            self.svm.latest_blockhash(),
        );
        self.svm
            .send_transaction(tx)
            .map(|_| ())
            .map_err(|e| format!("{:?}", e.err))
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



/// Full confidential-transfer view of an account.
struct CtView {
    pending_counter: u64,
    aes_balance: u64,
    pending: u64,
    available_ct: solana_zk_sdk::encryption::elgamal::ElGamalCiphertext,
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
        available_ct: ct.available_balance.try_into().unwrap(),
    }
}

fn deposit(env: &mut Env, acct: &CtAccount, mint: &Address, amount: u64) {
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
    env.send(&[ix], &[&acct.owner]).expect("deposit");
}

/// Builds ApplyPendingBalance from a snapshot taken at some earlier point.
/// Passing a stale snapshot is exactly what a racing client does.
fn apply_from_snapshot(env: &mut Env, acct: &CtAccount, expected_counter: u64, new_balance: u64) -> Result<(), String> {
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


/// Spends from the confidential available balance, using `claimed_balance` as
/// the client's idea of what it currently holds. That one parameter is the
/// whole experiment: pass the stale cached number and the proofs describe a
/// balance the chain does not agree with.
fn try_withdraw(
    env: &mut Env,
    acct: &CtAccount,
    mint: &Address,
    claimed_balance: u64,
    amount: u64,
) -> Result<(), String> {
    let v = view(env, acct);
    let proofs = withdraw_proof_data(&v.available_ct, claimed_balance, amount, &acct.elgamal)
        .map_err(|e| format!("proof generation: {:?}", e))?;

    let ixs = ct_ix::withdraw(
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
    .map_err(|e| format!("{:?}", e))?;

    env.send(&ixs, &[&acct.owner])
}


/// Confidential transfer, where `claimed` is the AES ciphertext the client
/// feeds proof generation as its current balance. Passing the account's stored
/// ciphertext is the naive path; passing one built locally over the recovered
/// balance is the fix.
fn try_transfer(
    env: &mut Env,
    src: &CtAccount,
    dst: &CtAccount,
    mint: &Address,
    claimed: &AeCiphertext,
    claimed_plain: u64,
    amount: u64,
) -> Result<(), String> {
    let v = view(env, src);
    let proofs = transfer_split_proof_data(
        &v.available_ct,
        claimed,
        amount,
        &src.elgamal,
        &src.aes,
        dst.elgamal.pubkey(),
        None,
    )
    .map_err(|e| format!("proof generation: {:?}", e))?;

    let ixs = ct_ix::transfer(
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
    .map_err(|e| format!("{:?}", e))?;

    env.send(&ixs, &[&src.owner])
}


/// Reproduces the ApplyPendingBalance race against the real token-2022 program,
/// then shows that the recovered balance is spendable while the cached one is not.
#[test]
fn stale_cache_is_detectable_recoverable_and_spendable() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = create_ct_account(&mut env, &mint.pubkey());

    env.send(
        &[token_ix::mint_to(
            &T22,
            &mint.pubkey(),
            &alice.address(),
            &env.payer.pubkey(),
            &[],
            2_000_000,
        )
        .unwrap()],
        &[],
    )
    .expect("mint_to");

    deposit(&mut env, &alice, &mint.pubkey(), 1_000_000);
    let v = view(&env, &alice);
    apply_from_snapshot(&mut env, &alice, v.pending_counter, v.aes_balance + v.pending).unwrap();

    // A clean apply leaves the cache correct and the counters equal.
    let data = env.account_data(&alice.address());
    assert_eq!(
        check_sync(&data, alice.elgamal.secret(), &alice.aes).unwrap(),
        SyncStatus::InSync {
            available: 1_000_000
        }
    );
    assert_eq!(counter_gap(&data).unwrap(), 0);

    // --- the race ---
    // The custodian reads, dust lands, and the apply it already built goes
    // through against a state that moved underneath it.
    let snapshot = view(&env, &alice);
    for amount in [1u64, 2, 3] {
        deposit(&mut env, &alice, &mint.pubkey(), amount);
    }
    apply_from_snapshot(
        &mut env,
        &alice,
        snapshot.pending_counter,
        snapshot.aes_balance + snapshot.pending,
    )
    .unwrap();

    // The program accepted it. Nothing failed, and the cache is now behind.
    let data = env.account_data(&alice.address());
    assert_eq!(
        check_sync(&data, alice.elgamal.secret(), &alice.aes).unwrap(),
        SyncStatus::Stale {
            aes_view: 1_000_000,
            missed: 6,
            truth: 1_000_006,
        }
    );
    assert_eq!(counter_gap(&data).unwrap(), 3);

    // --- spending on the cache is refused ---
    assert!(
        try_withdraw(&mut env, &alice, &mint.pubkey(), 1_000_000, 100).is_err(),
        "a spend built on the stale cache must not succeed"
    );

    // --- spending on the recovered balance works ---
    let data = env.account_data(&alice.address());
    let (truth, _) = spendable_balance(&data, alice.elgamal.secret(), &alice.aes).unwrap();
    assert_eq!(truth, 1_000_006);
    try_withdraw(&mut env, &alice, &mint.pubkey(), truth, 100).expect("recovered balance spendable");

    // And the account healed on the way through.
    let data = env.account_data(&alice.address());
    assert_eq!(
        check_sync(&data, alice.elgamal.secret(), &alice.aes).unwrap(),
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
    let alice = create_ct_account(&mut env, &mint.pubkey());
    let bob = create_ct_account(&mut env, &mint.pubkey());

    env.send(
        &[token_ix::mint_to(
            &T22,
            &mint.pubkey(),
            &alice.address(),
            &env.payer.pubkey(),
            &[],
            2_000_000,
        )
        .unwrap()],
        &[],
    )
    .expect("mint_to");

    deposit(&mut env, &alice, &mint.pubkey(), 1_000_000);
    let v = view(&env, &alice);
    apply_from_snapshot(&mut env, &alice, v.pending_counter, v.aes_balance + v.pending).unwrap();

    let snapshot = view(&env, &alice);
    for amount in [7u64, 11] {
        deposit(&mut env, &alice, &mint.pubkey(), amount);
    }
    apply_from_snapshot(
        &mut env,
        &alice,
        snapshot.pending_counter,
        snapshot.aes_balance + snapshot.pending,
    )
    .unwrap();

    let data = env.account_data(&alice.address());
    let stored = stored_decryptable(&env, &alice);
    assert_eq!(counter_gap(&data).unwrap(), 2);

    // Naive: feed proof generation the account's own stale ciphertext.
    assert!(
        try_transfer(&mut env, &alice, &bob, &mint.pubkey(), &stored, 1_000_000, 500).is_err(),
        "transfer built on the stale cache must not succeed"
    );

    // Fix: feed it the ciphertext spendable_balance returns.
    let (truth, corrected) =
        spendable_balance(&data, alice.elgamal.secret(), &alice.aes).unwrap();
    assert_eq!(truth, 1_000_018);
    try_transfer(&mut env, &alice, &bob, &mint.pubkey(), &corrected, truth, 500)
        .expect("corrected transfer accepted");

    let data = env.account_data(&alice.address());
    assert_eq!(
        check_sync(&data, alice.elgamal.secret(), &alice.aes).unwrap(),
        SyncStatus::InSync {
            available: 1_000_018 - 500
        }
    );
    assert_eq!(view(&env, &bob).pending, 500, "recipient credited");
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

/// The counter check can report a clean account that is not clean.
///
/// Both counters are account state and every apply overwrites them, so a read
/// sees whatever the most recent apply wrote. A second apply that was itself in
/// sync records equal counters over a balance the first apply already left
/// stale, and the staleness rides forward because that second client read the
/// stale cache and added its own pending to it.
///
/// Two workers on one account is a design error; a submit that times out and
/// gets retried is ordinary. Both produce this.
#[test]
fn a_second_apply_erases_the_evidence_of_the_first() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = create_ct_account(&mut env, &mint.pubkey());

    env.send(
        &[token_ix::mint_to(
            &T22,
            &mint.pubkey(),
            &alice.address(),
            &env.payer.pubkey(),
            &[],
            2_000_000,
        )
        .unwrap()],
        &[],
    )
    .expect("mint_to");

    deposit(&mut env, &alice, &mint.pubkey(), 1_000_000);
    let v = view(&env, &alice);
    apply_from_snapshot(&mut env, &alice, v.pending_counter, v.aes_balance + v.pending).unwrap();

    // Worker 1 snapshots, dust lands, worker 1's apply goes through stale.
    let snapshot = view(&env, &alice);
    deposit(&mut env, &alice, &mint.pubkey(), 9);
    apply_from_snapshot(
        &mut env,
        &alice,
        snapshot.pending_counter,
        snapshot.aes_balance + snapshot.pending,
    )
    .unwrap();

    // At this instant the counters do tell the truth.
    let data = env.account_data(&alice.address());
    assert_eq!(counter_gap(&data).unwrap(), 1);
    assert!(matches!(
        check_sync(&data, alice.elgamal.secret(), &alice.aes).unwrap(),
        SyncStatus::Stale { missed: 9, .. }
    ));

    // Worker 2 now applies. It reads the stale cache, adds a pending balance of
    // zero, and lands cleanly against the counter it read.
    let v2 = view(&env, &alice);
    apply_from_snapshot(&mut env, &alice, v2.pending_counter, v2.aes_balance + v2.pending).unwrap();

    // The counters now say the account is fine. It is not.
    let data = env.account_data(&alice.address());
    assert_eq!(
        counter_gap(&data).unwrap(),
        0,
        "the second apply overwrote the evidence"
    );
    assert_eq!(
        check_sync(&data, alice.elgamal.secret(), &alice.aes).unwrap(),
        SyncStatus::Stale {
            aes_view: 1_000_000,
            missed: 9,
            truth: 1_000_009,
        },
        "the ciphertext check still sees it"
    );

    // And the account really is unspendable on the cached number.
    assert!(try_withdraw(&mut env, &alice, &mint.pubkey(), 1_000_000, 100).is_err());
}

/// `actual` can land below `expected`, so the gap has to be computed
/// saturatingly or it underflows.
///
/// A client reads the counter, someone else's apply resets it to zero, a credit
/// lands, and then the first client's apply arrives carrying the old high value.
#[test]
fn actual_can_land_below_expected() {
    let mut env = Env::new();
    let mint = Keypair::new();
    create_mint(&mut env, &mint);
    let alice = create_ct_account(&mut env, &mint.pubkey());

    env.send(
        &[token_ix::mint_to(
            &T22,
            &mint.pubkey(),
            &alice.address(),
            &env.payer.pubkey(),
            &[],
            2_000_000,
        )
        .unwrap()],
        &[],
    )
    .expect("mint_to");

    // Build the counter up to 3.
    for amount in [100u64, 200, 300] {
        deposit(&mut env, &alice, &mint.pubkey(), amount);
    }
    let stale_snapshot = view(&env, &alice);
    assert_eq!(stale_snapshot.pending_counter, 3);

    // Someone else's apply resets the counter to zero.
    apply_from_snapshot(
        &mut env,
        &alice,
        stale_snapshot.pending_counter,
        stale_snapshot.aes_balance + stale_snapshot.pending,
    )
    .unwrap();

    // One credit lands, counter goes to 1.
    deposit(&mut env, &alice, &mint.pubkey(), 50);

    // The first client's apply finally arrives, still carrying expected = 3.
    let v = view(&env, &alice);
    apply_from_snapshot(&mut env, &alice, 3, v.aes_balance + v.pending).unwrap();

    let data = env.account_data(&alice.address());
    let state = StateWithExtensions::<Account>::unpack(&data).unwrap();
    let ct = state.get_extension::<ConfidentialTransferAccount>().unwrap();
    let expected = u64::from(ct.expected_pending_balance_credit_counter);
    let actual = u64::from(ct.actual_pending_balance_credit_counter);
    assert_eq!((expected, actual), (3, 1), "actual is below expected");

    // A naive `actual - expected` panics in debug and wraps in release.
    assert_eq!(counter_gap(&data).unwrap(), 0, "saturating, not wrapping");
}
