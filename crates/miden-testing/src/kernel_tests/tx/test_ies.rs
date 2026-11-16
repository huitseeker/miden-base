//! Transaction-host coverage for EcGFp5/Eidos integrated encryption.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_protocol::account::Account;
use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
use miden_protocol::crypto::ies::ecgfp5_eidos::{self, Envelope};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_protocol::transaction::{ExecutedTransaction, TransactionScript};
use miden_protocol::{Felt, WORD_SIZE};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_tx::LocalTransactionProver;

use crate::{Auth, MockChainBuilder};

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

    let account = Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce);
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    mock_chain.prove_next_block()?;
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

fn secret_key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 40]).expect("bytes should encode a valid secret key")
}

fn felts(values: [u32; 4]) -> Vec<Felt> {
    values.map(Felt::from).to_vec()
}
