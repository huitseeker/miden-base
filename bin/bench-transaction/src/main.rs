use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use miden_protocol::transaction::TransactionMeasurements;
use miden_testing::TransactionContext;

mod context_setups;
use context_setups::{
    tx_consume_single_p2id_note, tx_consume_two_p2id_notes, tx_create_single_p2id_note,
};

mod cycle_counting_benchmarks;
use cycle_counting_benchmarks::ExecutionBenchmark;
use cycle_counting_benchmarks::utils::{MeasurementsPrinter, write_bench_results_to_json};

async fn measure_transaction(
    setup: impl Fn() -> Result<TransactionContext>,
) -> Result<MeasurementsPrinter> {
    let tx_measurements = setup()?.execute().await.map(TransactionMeasurements::from)?;
    let (_executed_tx, trace_summary) = setup()?.execute_with_trace_summary().await?;

    Ok(MeasurementsPrinter::new(tx_measurements, trace_summary))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // create a template file for benchmark results
    let path = Path::new("bin/bench-transaction/bench-tx.json");
    let mut file = File::create(path).context("failed to create file")?;
    file.write_all(b"{}").context("failed to write to file")?;

    // run all available benchmarks
    let benchmark_results = vec![
        (
            ExecutionBenchmark::ConsumeSingleP2ID,
            measure_transaction(tx_consume_single_p2id_note).await?,
        ),
        (
            ExecutionBenchmark::ConsumeTwoP2ID,
            measure_transaction(tx_consume_two_p2id_notes).await?,
        ),
        (
            ExecutionBenchmark::CreateSingleP2ID,
            measure_transaction(tx_create_single_p2id_note).await?,
        ),
    ];

    // store benchmark results in the JSON file
    write_bench_results_to_json(path, benchmark_results)?;

    Ok(())
}
