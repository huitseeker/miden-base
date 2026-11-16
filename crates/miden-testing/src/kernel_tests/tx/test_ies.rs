//! Transaction-host coverage for EcGFp5/Eidos integrated encryption.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_protocol::account::Account;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
use miden_protocol::crypto::ies::ecgfp5_eidos::{self, Envelope};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::{
    ExecutedTransaction,
    IesSealSecret,
    InputNote,
    TransactionScript,
};
use miden_protocol::{Felt, WORD_SIZE, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{
    LocalTransactionProver,
    NoteCheckerError,
    NoteConsumptionChecker,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionKernelError,
};

use crate::utils::create_public_p2any_note;
use crate::{Auth, MockChain, MockChainBuilder};

const PLAINTEXT: [u32; 4] = [11, 22, 33, 44];
const CONTEXT: [u32; 4] = [5, 6, 7, 8];
const PLAINTEXT_PTR: u32 = 0;
const CONTEXT_PTR: u32 = PLAINTEXT_PTR + PLAINTEXT.len() as u32;
const ENVELOPE_PTR: u32 = CONTEXT_PTR + CONTEXT.len() as u32;
const ENVELOPE_LEN: u32 = 8 + 2 * PLAINTEXT.len() as u32;
const ENVELOPE_NUM_WORDS: u32 = ENVELOPE_LEN / WORD_SIZE as u32;

/// Execution draws and records an ephemeral secret; proving replays it and preserves the envelope.
#[tokio::test]
async fn ies_seal_executes_and_proves_with_recorded_secret() -> anyhow::Result<()> {
    let recipient_secret = secret_key(1);
    let recipient = recipient_secret.public_key();
    let tx_script = compile_tx_script(recipient.to_elements())?;

    let (mock_chain, account) = mock_chain_and_account()?;
    let executed_tx = mock_chain
        .build_transaction(account)
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    let envelope = envelope(&executed_tx)?;
    let plaintext = ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &envelope)?;
    assert_eq!(plaintext, felts(PLAINTEXT));

    let secrets = executed_tx.tx_inputs().ies_seal_secrets();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].recipient(), recipient);
    assert_eq!(envelope.ephemeral_key(), secrets[0].ephemeral_secret().public_key());

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// A supplied secret fixes the envelope during execution and proving without drawing another one.
#[tokio::test]
async fn ies_seal_executes_and_proves_with_supplied_secret() -> anyhow::Result<()> {
    let recipient_secret = secret_key(1);
    let recipient = recipient_secret.public_key();
    let seal_secret = IesSealSecret::new(recipient, secret_key(2));
    let tx_script = compile_tx_script(recipient.to_elements())?;

    let (mock_chain, account) = mock_chain_and_account()?;
    let executed_tx = mock_chain
        .build_transaction(account)
        .tx_script(tx_script)
        .add_ies_seal_secret(seal_secret.clone())
        .build()?
        .execute()
        .await?;

    let envelope = envelope(&executed_tx)?;
    let plaintext = ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &envelope)?;
    assert_eq!(plaintext, felts(PLAINTEXT));
    assert_eq!(envelope.ephemeral_key(), seal_secret.ephemeral_secret().public_key());
    assert_eq!(executed_tx.tx_args().ies_seal_secrets(), core::slice::from_ref(&seal_secret));
    assert!(executed_tx.tx_inputs().ies_seal_secrets().is_empty());

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// Note checking and execution reject a supplied secret bound to another recipient.
#[tokio::test]
async fn ies_seal_rejects_a_secret_for_another_recipient() -> anyhow::Result<()> {
    let requested = secret_key(1).public_key();
    let supplied = secret_key(2).public_key();
    let tx_script = compile_tx_script(requested.to_elements())?;
    let note =
        create_public_p2any_note(ACCOUNT_ID_SENDER.try_into().unwrap(), [FungibleAsset::mock(100)]);

    let (mock_chain, account) = mock_chain_and_account()?;
    let mock_tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_note(note.clone())
        .tx_script(tx_script)
        .add_ies_seal_secret(IesSealSecret::new(supplied, secret_key(3)))
        .build()?;

    let checker_error = {
        let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx);
        NoteConsumptionChecker::new(&executor)
            .can_consume(
                mock_tx.account().id(),
                mock_tx.tx_inputs().block_header().block_num(),
                InputNote::unauthenticated(note),
                mock_tx.tx_args().clone(),
            )
            .await
            .unwrap_err()
    };
    let NoteCheckerError::TransactionPreparation(checker_error) = checker_error else {
        anyhow::bail!("expected transaction preparation failure, got {checker_error}");
    };
    assert_recipient_mismatch(checker_error, supplied.to_commitment(), requested.to_commitment());

    let execution_error = mock_tx.execute().await.unwrap_err();
    assert_recipient_mismatch(execution_error, supplied.to_commitment(), requested.to_commitment());

    Ok(())
}

/// Reduced note-set trials retain supplied secrets for the notes that remain.
#[tokio::test]
async fn ies_seal_checker_replays_remaining_secrets_for_a_reduced_note_set() -> anyhow::Result<()> {
    let first_recipient = secret_key(1).public_key();
    let second_recipient = secret_key(2).public_key();
    let failing_note = ies_note(first_recipient.to_elements(), true)?;
    let successful_note = ies_note(second_recipient.to_elements(), false)?;
    let notes = vec![failing_note.clone(), successful_note.clone()];

    let (mock_chain, account) = mock_chain_and_account()?;
    let mock_tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(notes.clone())
        .add_ies_seal_secret(IesSealSecret::new(first_recipient, secret_key(3)))
        .add_ies_seal_secret(IesSealSecret::new(second_recipient, secret_key(4)))
        .build()?;

    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx);
    let consumption_info = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            notes,
            mock_tx.tx_args().clone(),
        )
        .await?;

    assert_eq!(consumption_info.successful().len(), 1);
    assert_eq!(consumption_info.successful()[0].note().id(), successful_note.id());
    assert_eq!(consumption_info.failed().len(), 1);
    assert_eq!(consumption_info.failed()[0].note().id(), failing_note.id());

    Ok(())
}

/// Reduced note-set trials validate supplied secrets first reached after an earlier note fails.
#[tokio::test]
async fn ies_seal_checker_validates_a_later_note_secret_after_failure() -> anyhow::Result<()> {
    let first_recipient = secret_key(1).public_key();
    let second_recipient = secret_key(2).public_key();
    let wrong_recipient = secret_key(3).public_key();
    let failing_note = ies_note(first_recipient.to_elements(), true)?;
    let later_note = ies_note(second_recipient.to_elements(), false)?;
    let notes = vec![failing_note, later_note];

    let (mock_chain, account) = mock_chain_and_account()?;
    let mock_tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(notes.clone())
        .add_ies_seal_secret(IesSealSecret::new(first_recipient, secret_key(4)))
        .add_ies_seal_secret(IesSealSecret::new(wrong_recipient, secret_key(5)))
        .build()?;

    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx);
    let checker_error = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            notes,
            mock_tx.tx_args().clone(),
        )
        .await
        .unwrap_err();

    let NoteCheckerError::TransactionPreparation(checker_error) = checker_error else {
        anyhow::bail!("expected transaction preparation failure, got {checker_error}");
    };
    assert_recipient_mismatch(
        checker_error,
        wrong_recipient.to_commitment(),
        second_recipient.to_commitment(),
    );

    Ok(())
}

/// Note checking and execution reject a supplied secret when there is no IES `seal` request.
#[tokio::test]
async fn ies_seal_rejects_an_unused_secret() -> anyhow::Result<()> {
    let recipient = secret_key(1).public_key();
    let (mock_chain, account) = mock_chain_and_account()?;
    let note: Note = P2idNote::builder()
        .sender(ACCOUNT_ID_SENDER.try_into().unwrap())
        .target(account.id())
        .serial_number(Word::from([1u32, 2, 3, 4]))
        .asset(FungibleAsset::mock(100))
        .note_type(NoteType::Public)
        .build()?
        .into();
    let mock_tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_note(note.clone())
        .add_ies_seal_secret(IesSealSecret::new(recipient, secret_key(2)))
        .build()?;

    let checker_error = {
        let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx);
        NoteConsumptionChecker::new(&executor)
            .can_consume(
                mock_tx.account().id(),
                mock_tx.tx_inputs().block_header().block_num(),
                InputNote::unauthenticated(note),
                mock_tx.tx_args().clone(),
            )
            .await
            .unwrap_err()
    };
    assert_matches!(
        checker_error,
        NoteCheckerError::TransactionPreparation(TransactionExecutorError::UnusedIesSealSecrets(1))
    );

    let result = mock_tx.execute().await;
    assert_matches!(result, Err(TransactionExecutorError::UnusedIesSealSecrets(1)));

    Ok(())
}

fn compile_tx_script(recipient: [Felt; 5]) -> anyhow::Result<TransactionScript> {
    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::ies
        use miden::protocol::output_note

        @transaction_script
        pub proc main
            {store_inputs}
            push.{ENVELOPE_PTR} push.{context_len} push.{CONTEXT_PTR}
            push.{plaintext_len} push.{PLAINTEXT_PTR}
            {recipient}
            exec.ies::seal
            # => []

            push.1.2.3.4
            push.{note_type}
            push.0
            call.::mock::account::create_note
            # => [note_idx, pad(15)]

            dup push.{ENVELOPE_PTR} push.{ENVELOPE_NUM_WORDS} push.1
            exec.output_note::add_attachment_from_memory
            # => [note_idx, pad(15)]

            exec.sys::truncate_stack
        end
        "#,
        store_inputs = store_inputs(),
        context_len = CONTEXT.len(),
        plaintext_len = PLAINTEXT.len(),
        recipient = push_reversed(&recipient),
        note_type = NoteType::Private.as_u8(),
    );

    CodeBuilder::with_mock_packages()
        .compile_tx_script(code)
        .context("failed to compile IES transaction script")
}

fn ies_note(recipient: [Felt; 5], fail_after_seal: bool) -> anyhow::Result<Note> {
    let failure = if fail_after_seal { "push.1 push.0 div" } else { "" };
    let code = format!(
        r#"
        use miden::protocol::ies

        @note_script
        pub proc main
            {store_inputs}
            push.{ENVELOPE_PTR} push.{context_len} push.{CONTEXT_PTR}
            push.{plaintext_len} push.{PLAINTEXT_PTR}
            {recipient}
            exec.ies::seal
            {failure}
        end
        "#,
        store_inputs = store_inputs(),
        context_len = CONTEXT.len(),
        plaintext_len = PLAINTEXT.len(),
        recipient = push_reversed(&recipient),
    );

    Ok(NoteBuilder::new(ACCOUNT_ID_SENDER.try_into().unwrap(), &mut rand::rng())
        .code(code)
        .build()?)
}

fn store_inputs() -> String {
    let store = |ptr: u32, values: [u32; 4]| {
        values
            .iter()
            .enumerate()
            .map(|(idx, value)| format!("push.{value} push.{} mem_store", ptr + idx as u32))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!("{}\n{}", store(PLAINTEXT_PTR, PLAINTEXT), store(CONTEXT_PTR, CONTEXT))
}

fn push_reversed(elements: &[Felt]) -> String {
    elements
        .iter()
        .rev()
        .map(|element| format!("push.{element}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn envelope(executed_tx: &ExecutedTransaction) -> anyhow::Result<Envelope> {
    let attachment = executed_tx
        .output_notes()
        .get_note(0)
        .attachments()
        .get(0)
        .context("output note should carry the envelope")?;
    Ok(Envelope::from_elements(attachment.as_elements())?)
}

fn mock_chain_and_account() -> anyhow::Result<(MockChain, Account)> {
    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    mock_chain.prove_next_block()?;
    Ok((mock_chain, account))
}

fn assert_recipient_mismatch(error: TransactionExecutorError, supplied: Word, requested: Word) {
    assert_matches!(
        error,
        TransactionExecutorError::TransactionProgramExecutionFailed(ExecutionError::EventError {
            error,
            ..
        }) => {
            assert_matches!(
                *error.downcast::<TransactionKernelError>().unwrap(),
                TransactionKernelError::IesSealSecretRecipientMismatch {
                    supplied: actual_supplied,
                    requested: actual_requested,
                } => {
                    assert_eq!(actual_supplied, supplied);
                    assert_eq!(actual_requested, requested);
                }
            );
        }
    );
}

fn secret_key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 40]).expect("bytes should encode a valid secret key")
}

fn felts(values: [u32; 4]) -> Vec<Felt> {
    values.map(Felt::from).to_vec()
}
