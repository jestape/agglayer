//! Proves a directory of ZisK pessimistic proof inputs, as written by
//! `zisk-inputs`, end to end, and reports how long each step takes.
//!
//! For every input it runs the native pessimistic proof, proves the input with
//! ZisK (optionally wrapping the proof in PLONK and verifying it), and checks
//! that the proof's public values are the native output. One CSV row is written
//! per input as soon as it is done, and a summary is printed at the end.
//!
//! With `--execute-only` it runs the ZisK emulator instead of the prover, which
//! needs no proving key, to check a batch of inputs or this tool itself.

use std::{
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::Parser;
use eyre::{eyre, Context as _};
use pessimistic_proof::{core::generate_pessimistic_proof, PessimisticProofOutput};
use pessimistic_proof_test_suite::zisk::{aggchain_vkey, read_witness, Kind};
use zisk_sdk::{
    EmbeddedExecuteOnlyBuilder, EmbeddedExecuteOnlyClient, EmbeddedOpts, GuestProgram, ProofKind,
    PublicValues, ZiskClient, ZiskStdin,
};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Directory of input files (`*.bin`), as written by `zisk-inputs`.
    #[clap(long)]
    inputs: PathBuf,

    /// Only prove inputs of this kind. Can be repeated; defaults to all
    /// kinds.
    #[clap(long = "kind", value_enum)]
    kinds: Vec<Kind>,

    /// Prove at most this many inputs, in file name order, after the `--kind`
    /// filter.
    #[clap(long)]
    limit: Option<usize>,

    /// CSV file the per-input results are written to.
    #[clap(long, default_value = "zisk-prove.csv")]
    out: PathBuf,

    /// Run the ZisK emulator instead of proving. Needs no proving key.
    #[clap(long)]
    execute_only: bool,

    /// Prove on a remote ZisK proving service instead of in this process.
    #[clap(long, conflicts_with_all = [
        "proving_key",
        "proving_key_plonk",
        "gpu",
        "minimal_memory",
        "max_streams",
        "max_recursive_streams",
        "max_witness_stored",
    ])]
    remote: Option<String>,

    /// ZisK proving key directory. Defaults to the ZisK installation's.
    #[clap(long)]
    proving_key: Option<PathBuf>,

    /// ZisK PLONK proving key directory. Defaults to the ZisK installation's.
    #[clap(long)]
    proving_key_plonk: Option<PathBuf>,

    /// Prove on a GPU.
    #[clap(long)]
    gpu: bool,

    /// Run the memory operations planner on the CPU, even with `--gpu`.
    #[clap(long, requires = "gpu")]
    cpu_mops: bool,

    /// Reduce the prover's memory footprint, at the cost of speed.
    #[clap(long)]
    minimal_memory: bool,

    /// Maximum number of parallel proving streams. Fewer streams use less GPU
    /// memory.
    #[clap(long)]
    max_streams: Option<usize>,

    /// Maximum number of recursive (aggregation) streams per GPU.
    #[clap(long)]
    max_recursive_streams: Option<usize>,

    /// Maximum memory, in bytes, used to store witnesses while proving.
    #[clap(long)]
    max_witness_stored: Option<usize>,

    /// Wrap each proof in PLONK, as on-chain verification needs, and time it
    /// separately.
    #[clap(long)]
    plonk: bool,

    /// Verify each proof (the PLONK one with `--plonk`), and time it.
    #[clap(long)]
    verify: bool,

    /// Save each proof to this directory, as `<input>.proof`.
    #[clap(long)]
    save_proofs: Option<PathBuf>,
}

/// What the native pessimistic proof does with an input.
enum Native {
    Accepted(PessimisticProofOutput),
    Rejected(String),
}

/// The result of one input.
#[derive(Default)]
struct Row {
    input: String,
    network: u32,
    bridge_exits: usize,
    imported_bridge_exits: usize,
    /// How the certificate is authorized: `ecdsa`, `multisig` or
    /// `multisig+aggchain` (a multisig and an SP1 aggchain proof).
    kind: &'static str,
    /// Vkey of the aggchain program, for `multisig+aggchain` certificates.
    aggchain_vkey: Option<String>,
    native: String,
    steps: Option<u64>,
    cost: Option<u64>,
    /// Emulator time with `--execute-only`, otherwise the prover's own
    /// proving time.
    zisk_ms: Option<u64>,
    /// Wall-clock time of the prove (or execute) call.
    wall_ms: Option<u64>,
    wrap_ms: Option<u64>,
    verify_ms: Option<u64>,
    proof_bytes: Option<usize>,
    /// Whether the proof's public values are the native output.
    output_matches: Option<bool>,
    error: Option<String>,
}

const CSV_HEADER: &str = "input,network,bridge_exits,imported_bridge_exits,kind,aggchain_vkey,\
                          native,steps,cost,zisk_ms,wall_ms,wrap_ms,verify_ms,proof_bytes,\
                          output_matches,error";

impl Row {
    fn csv(&self) -> String {
        fn opt<T: ToString>(value: &Option<T>) -> String {
            value.as_ref().map(T::to_string).unwrap_or_default()
        }
        let quote = |text: &str| format!("\"{}\"", text.replace('"', "'"));
        [
            self.input.clone(),
            self.network.to_string(),
            self.bridge_exits.to_string(),
            self.imported_bridge_exits.to_string(),
            self.kind.to_string(),
            opt(&self.aggchain_vkey),
            quote(&self.native),
            opt(&self.steps),
            opt(&self.cost),
            opt(&self.zisk_ms),
            opt(&self.wall_ms),
            opt(&self.wrap_ms),
            opt(&self.verify_ms),
            opt(&self.proof_bytes),
            opt(&self.output_matches),
            self.error.as_deref().map(quote).unwrap_or_default(),
        ]
        .join(",")
    }
}

/// The ZisK client: a prover, or the emulator with `--execute-only`. The ZisK
/// SDK allows a single prover client per process.
enum Zisk {
    Prover(Box<ZiskClient>),
    Emulator(EmbeddedExecuteOnlyClient),
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    tokio::runtime::Runtime::new()?.block_on(run(args))
}

async fn run(args: Args) -> eyre::Result<()> {
    let mut inputs: Vec<PathBuf> = std::fs::read_dir(&args.inputs)
        .with_context(|| format!("reading {}", args.inputs.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()?;
    inputs.retain(|path| path.extension().is_some_and(|extension| extension == "bin"));
    inputs.sort();
    if !args.kinds.is_empty() {
        inputs.retain(|path| match read_witness(path) {
            Ok((_, header)) => args.kinds.contains(&Kind::of(&header)),
            Err(error) => {
                println!("{}: skipped, unreadable: {error}", path.display());
                false
            }
        });
    }
    inputs.truncate(args.limit.unwrap_or(inputs.len()));
    if inputs.is_empty() {
        return Err(eyre!("no *.bin input in {}", args.inputs.display()));
    }
    if let Some(dir) = &args.save_proofs {
        std::fs::create_dir_all(dir)?;
    }

    let program =
        GuestProgram::from_bytes("pessimistic-proof", pessimistic_proof::zisk::ELF.to_vec());
    let setup_start = Instant::now();
    let zisk = connect(&args, &program).await?;
    let setup = setup_start.elapsed();
    println!("setup: {}", ms(setup));

    let mut csv =
        File::create(&args.out).with_context(|| format!("creating {}", args.out.display()))?;
    writeln!(csv, "{CSV_HEADER}")?;

    let run_start = Instant::now();
    let mut rows = Vec::with_capacity(inputs.len());
    for (index, path) in inputs.iter().enumerate() {
        let row = process(&args, &zisk, &program, path).await;
        writeln!(csv, "{}", row.csv())?;
        csv.flush()?;
        println!(
            "[{}/{}] {}: {}",
            index + 1,
            inputs.len(),
            row.input,
            match (&row.error, row.output_matches) {
                (Some(error), _) => format!("error: {error}"),
                (None, Some(false)) => "OUTPUT MISMATCH".to_string(),
                (None, _) => format!(
                    "{} steps, zisk {} ms, wall {} ms{}{}",
                    row.steps.unwrap_or_default(),
                    row.zisk_ms.unwrap_or_default(),
                    row.wall_ms.unwrap_or_default(),
                    row.wrap_ms
                        .map(|wrap| format!(", wrap {wrap} ms"))
                        .unwrap_or_default(),
                    row.verify_ms
                        .map(|verify| format!(", verify {verify} ms"))
                        .unwrap_or_default(),
                ),
            }
        );
        rows.push(row);
    }

    summarize(&rows, setup, run_start.elapsed());
    println!("results: {}", args.out.display());
    Ok(())
}

async fn connect(args: &Args, program: &GuestProgram) -> eyre::Result<Zisk> {
    if args.execute_only {
        let client = EmbeddedExecuteOnlyBuilder::new().emulator().build()?;
        client.setup(program, false)?;
        return Ok(Zisk::Emulator(client));
    }

    let client = match &args.remote {
        Some(url) => ZiskClient::remote(url.clone()).build()?,
        None => {
            let mut opts = EmbeddedOpts::default();
            if args.minimal_memory {
                opts = opts.minimal_memory();
            }
            if let Some(max) = args.max_streams {
                opts = opts.max_streams(max);
            }
            if let Some(max) = args.max_recursive_streams {
                opts = opts.max_recursive_streams(max);
            }
            if let Some(max) = args.max_witness_stored {
                opts = opts.max_witness_stored(max);
            }
            let mut builder = ZiskClient::embedded().with_embedded_opts(opts);
            if args.plonk {
                builder = builder.plonk();
            }
            if let Some(path) = &args.proving_key {
                builder = builder.proving_key(path);
            }
            if let Some(path) = &args.proving_key_plonk {
                builder = builder.proving_key_plonk(path);
            }
            if args.gpu {
                builder = builder.gpu();
            }
            if args.cpu_mops {
                builder = builder.cpu_mops();
            }
            builder.build()?
        }
    };
    client.setup(program).run()?.await?;
    Ok(Zisk::Prover(Box::new(client)))
}

async fn process(args: &Args, zisk: &Zisk, program: &GuestProgram, path: &Path) -> Row {
    let mut row = Row {
        input: path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ..Default::default()
    };
    if let Err(error) = prove(args, zisk, program, path, &mut row).await {
        row.error = Some(format!("{error:#}"));
    }
    row
}

async fn prove(
    args: &Args,
    zisk: &Zisk,
    program: &GuestProgram,
    path: &Path,
    row: &mut Row,
) -> eyre::Result<()> {
    // The input starts with the network state and the batch header, which the
    // native pessimistic proof takes too.
    let (state, header) = read_witness(path)?;
    row.network = header.origin_network.to_u32();
    row.bridge_exits = header.bridge_exits.len();
    row.imported_bridge_exits = header.imported_bridge_exits.len();
    row.kind = Kind::of(&header).as_str();
    row.aggchain_vkey = aggchain_vkey(&header);

    // The native execution does not verify aggchain proofs: only the guest
    // does.
    let native = match generate_pessimistic_proof(state, &header) {
        Ok((output, _)) => Native::Accepted(output),
        Err(error) => Native::Rejected(error.to_string()),
    };
    row.native = match &native {
        Native::Accepted(_) => "accepted".to_string(),
        Native::Rejected(error) => format!("rejected: {error}"),
    };

    let stdin = ZiskStdin::from_file(path)?;
    let start = Instant::now();
    let publics = match zisk {
        Zisk::Emulator(client) => {
            let output = client.execute(program, stdin, None, None)?;
            row.wall_ms = Some(millis(start.elapsed()));
            row.steps = Some(output.get_execution_steps());
            row.cost = output.get_execution_cost();
            row.zisk_ms = Some(output.get_execution_time());
            output.get_publics().clone()
        }
        Zisk::Prover(client) => {
            let proved = client.prove(program, stdin).run()?.await?;
            row.wall_ms = Some(millis(start.elapsed()));
            row.steps = Some(proved.get_execution_steps());
            row.cost = Some(proved.get_execution_cost());
            row.zisk_ms = Some(proved.get_proving_time());

            let mut proof = proved.get_proof().clone();
            if args.plonk {
                let start = Instant::now();
                let wrapped = client.wrap_proof(&proof, ProofKind::Plonk).run()?.await?;
                row.wrap_ms = Some(millis(start.elapsed()));
                proof = wrapped.get_proof().clone();
            }
            row.proof_bytes = Some(proof.get_proof_bytes()?.len());
            if args.verify {
                let start = Instant::now();
                proof.verify()?;
                row.verify_ms = Some(millis(start.elapsed()));
            }
            if let Some(dir) = &args.save_proofs {
                proof.save(dir.join(format!("{}.proof", row.input)))?;
            }
            proved.get_publics()
        }
    };

    row.output_matches = Some(match native {
        Native::Accepted(expected) => decode(&publics)? == expected,
        // ZisK proved an input the native execution rejects.
        Native::Rejected(_) => false,
    });
    Ok(())
}

/// Decodes the program's public values: each public holds one 32-bit word the
/// program wrote, and the words make up the zero-padded output.
fn decode(publics: &PublicValues) -> eyre::Result<PessimisticProofOutput> {
    let bytes = publics
        .public_u64()
        .into_iter()
        .map(|word| u32::try_from(word).map(u32::to_le_bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| eyre!("a public value exceeds 32 bits"))?
        .concat();
    Ok(pessimistic_proof::zisk::decode_output(&bytes)?)
}

fn summarize(rows: &[Row], setup: Duration, total: Duration) {
    let failed = rows.iter().filter(|row| row.error.is_some()).count();
    let mismatched = rows
        .iter()
        .filter(|row| row.output_matches == Some(false))
        .count();
    println!();
    println!(
        "{} inputs: {} ok, {} errors, {} output mismatches; setup {}, total {}",
        rows.len(),
        rows.len() - failed - mismatched,
        failed,
        mismatched,
        ms(setup),
        ms(total),
    );

    let ok: Vec<&Row> = rows.iter().filter(|row| row.error.is_none()).collect();
    for kind in Kind::ALL.map(Kind::as_str) {
        let of_kind: Vec<&Row> = ok.iter().copied().filter(|row| row.kind == kind).collect();
        if of_kind.is_empty() {
            continue;
        }
        println!("{} {kind} certificates:", of_kind.len());
        for (name, values) in [
            (
                "steps",
                of_kind
                    .iter()
                    .filter_map(|row| row.steps)
                    .collect::<Vec<_>>(),
            ),
            (
                "zisk ms",
                of_kind.iter().filter_map(|row| row.zisk_ms).collect(),
            ),
            (
                "wall ms",
                of_kind.iter().filter_map(|row| row.wall_ms).collect(),
            ),
            (
                "wrap ms",
                of_kind.iter().filter_map(|row| row.wrap_ms).collect(),
            ),
            (
                "verify ms",
                of_kind.iter().filter_map(|row| row.verify_ms).collect(),
            ),
            (
                "proof bytes",
                of_kind
                    .iter()
                    .filter_map(|row| row.proof_bytes.map(|bytes| bytes as u64))
                    .collect(),
            ),
        ] {
            if let Some(stats) = Stats::of(values) {
                println!("  {name:<12} {stats}");
            }
        }
    }

    // The aggchain programs seen, as the cost of a certificate may depend on
    // the program whose proof it carries.
    let mut programs: std::collections::BTreeMap<&str, Vec<u64>> = Default::default();
    for row in &ok {
        if let Some(vkey) = &row.aggchain_vkey {
            programs.entry(vkey).or_default().extend(row.zisk_ms);
        }
    }
    if !programs.is_empty() {
        println!("aggchain programs:");
        for (vkey, times) in programs {
            let median = Stats::of(times)
                .map(|stats| stats.p50.to_string())
                .unwrap_or_default();
            println!(
                "  {vkey}  {} certificates (counted with a time), median zisk ms {median}",
                ok.iter()
                    .filter(|row| row.aggchain_vkey.as_deref() == Some(vkey))
                    .count()
            );
        }
    }
}

struct Stats {
    min: u64,
    p50: u64,
    p90: u64,
    p99: u64,
    max: u64,
    mean: u64,
}

impl Stats {
    fn of(mut values: Vec<u64>) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        let at = |quantile: f64| values[((values.len() - 1) as f64 * quantile).round() as usize];
        Some(Self {
            min: values[0],
            p50: at(0.5),
            p90: at(0.9),
            p99: at(0.99),
            max: values[values.len() - 1],
            mean: values.iter().sum::<u64>() / values.len() as u64,
        })
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "min {} | p50 {} | p90 {} | p99 {} | max {} | mean {}",
            self.min, self.p50, self.p90, self.p99, self.max, self.mean
        )
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn ms(duration: Duration) -> String {
    format!("{} ms", millis(duration))
}
