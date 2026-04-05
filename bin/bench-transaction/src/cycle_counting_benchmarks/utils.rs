extern crate alloc;
pub use alloc::collections::BTreeMap;
pub use alloc::string::String;
use std::fs::{read_to_string, write};
use std::path::Path;

use anyhow::Context;
use miden_protocol::transaction::TransactionMeasurements;
use miden_tx::TraceLenSummary;
use serde::Serialize;
use serde_json::{Value, from_str, to_string_pretty};

use super::ExecutionBenchmark;

// MEASUREMENTS PRINTER
// ================================================================================================

/// Helper structure holding the cycle count of each transaction stage which could be easily
/// converted to the JSON file.
#[derive(Debug, Clone, Serialize)]
pub struct MeasurementsPrinter {
    prologue: usize,
    notes_processing: usize,
    note_execution: BTreeMap<String, usize>,
    tx_script_processing: usize,
    epilogue: EpilogueMeasurements,
    poseidon2: Poseidon2Measurements,
}

impl MeasurementsPrinter {
    pub fn new(tx_measurements: TransactionMeasurements, trace_summary: TraceLenSummary) -> Self {
        let note_execution_map = tx_measurements
            .note_execution
            .iter()
            .map(|(id, len)| (id.to_hex(), *len))
            .collect();

        MeasurementsPrinter {
            prologue: tx_measurements.prologue,
            notes_processing: tx_measurements.notes_processing,
            note_execution: note_execution_map,
            tx_script_processing: tx_measurements.tx_script_processing,
            epilogue: EpilogueMeasurements::from_parts(
                tx_measurements.epilogue,
                tx_measurements.auth_procedure,
                tx_measurements.after_tx_cycles_obtained,
            ),
            poseidon2: Poseidon2Measurements::from_trace_summary(trace_summary),
        }
    }
}

/// Helper structure holding the cycle count for different intervals in the epilogue, namely:
/// - `total` interval holds the total number of cycles required to execute the epilogue
/// - `auth_procedure` interval holds the number of cycles required to execute the authentication
///   procedure
/// - `after_tx_cycles_obtained` holds the number of cycles which was executed from the moment of
///   the cycle count obtainment in the `epilogue::compute_fee` procedure to the end of the
///   epilogue.
#[derive(Debug, Clone, Serialize)]
struct EpilogueMeasurements {
    total: usize,
    auth_procedure: usize,
    after_tx_cycles_obtained: usize,
}

impl EpilogueMeasurements {
    pub fn from_parts(
        total: usize,
        auth_procedure: usize,
        after_tx_cycles_obtained: usize,
    ) -> Self {
        Self {
            total,
            auth_procedure,
            after_tx_cycles_obtained,
        }
    }
}

/// Helper structure holding a didactic summary of how Poseidon2 usage is counted from the VM
/// trace without performing any string-heavy work in the hot execution path.
#[derive(Debug, Clone, Serialize)]
struct Poseidon2Measurements {
    hash_chiplet_rows: usize,
    rows_per_permutation: usize,
    total_permutations: usize,
    sampled_work: [Poseidon2SampledWork; 4],
    excluded_work: &'static str,
}

impl Poseidon2Measurements {
    const ROWS_PER_PERMUTATION: usize = 32;

    fn from_trace_summary(trace_summary: TraceLenSummary) -> Self {
        let hash_chiplet_rows = trace_summary.chiplets_trace_len().hash_chiplet_len();
        debug_assert_eq!(
            hash_chiplet_rows % Self::ROWS_PER_PERMUTATION,
            0,
            "hash chiplet rows should be a multiple of the Poseidon2 cycle length"
        );

        Self {
            hash_chiplet_rows,
            rows_per_permutation: Self::ROWS_PER_PERMUTATION,
            total_permutations: hash_chiplet_rows / Self::ROWS_PER_PERMUTATION,
            sampled_work: [
                Poseidon2SampledWork {
                    op: "HPERM",
                    counting_rule: "each invocation contributes 1 Poseidon2 permutation",
                },
                Poseidon2SampledWork {
                    op: "MPVERIFY",
                    counting_rule: "each Merkle path node contributes 1 Poseidon2 permutation",
                },
                Poseidon2SampledWork {
                    op: "MRUPDATE",
                    counting_rule: "each Merkle path node contributes 2 Poseidon2 permutations",
                },
                Poseidon2SampledWork {
                    op: "VM control-block hashing",
                    counting_rule: "included when the VM routes the work through the hash chiplet",
                },
            ],
            excluded_work: "host-side Rust Poseidon2 calls outside VM execution are not counted",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct Poseidon2SampledWork {
    op: &'static str,
    counting_rule: &'static str,
}

/// Writes the provided benchmark results to the JSON file at the provided path.
pub fn write_bench_results_to_json(
    path: &Path,
    tx_benchmarks: Vec<(ExecutionBenchmark, MeasurementsPrinter)>,
) -> anyhow::Result<()> {
    // convert benchmark file internals to the JSON Value
    let benchmark_file = read_to_string(path).context("failed to read benchmark file")?;
    let mut benchmark_json: Value =
        from_str(&benchmark_file).context("failed to convert benchmark contents to json")?;

    // fill benchmarks JSON with results of each benchmark
    for (bench_type, tx_progress) in tx_benchmarks {
        let tx_benchmark_json = serde_json::to_value(tx_progress)
            .context("failed to convert tx measurements to json")?;

        benchmark_json[bench_type.to_string()] = tx_benchmark_json;
    }

    // write the benchmarks JSON to the results file
    write(
        path,
        to_string_pretty(&benchmark_json).expect("failed to convert json to String"),
    )
    .context("failed to write benchmark results to file")?;

    Ok(())
}
