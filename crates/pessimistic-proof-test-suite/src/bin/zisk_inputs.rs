//! Writes input files for the ZisK pessimistic proof program, to run with
//! `ziskemu -i` or `cargo-zisk execute/prove -i`.
//!
//! An input is the guest's stdin: the `NetworkState`, the `MultiBatchHeader`
//! and, if the certificate carries one, the SP1 compressed aggchain proof.

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use agglayer_types::{
    aggchain_data::CertificateAggchainDataCtx, L1WitnessCtx, PessimisticRootInput,
};
use clap::{Parser, Subcommand};
use eyre::{eyre, Context as _};
use pessimistic_proof::{
    core::{commitment::PessimisticRootCommitmentVersion, generate_pessimistic_proof},
    multi_batch_header::MultiBatchHeader,
    NetworkState,
};
use pessimistic_proof_test_suite::{
    runner::Runner,
    sample_data::{self as data},
    zisk::{read_witness, Kind, ZiskStdin},
};
use sp1_sdk::{
    network::proto::{
        base_network::prover_network_client::ProverNetworkClient,
        base_types::{
            FulfillmentStatus, GetFilteredProofRequestsRequest, GetProofRequestDetailsRequest,
            ProofRequest,
        },
    },
    HashableKey as _, SP1Stdin,
};

/// RPC of the Succinct prover network the Agglayer requests its proofs from
/// (explorer: <https://explorer.reserved.succinct.xyz>).
const SUCCINCT_RPC: &str = "https://rpc.production.succinct.xyz";

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Directory the input files are written to.
    #[clap(long, default_value = "zisk-inputs")]
    out_dir: PathBuf,

    #[clap(subcommand)]
    source: Source,
}

#[derive(Subcommand, Debug)]
enum Source {
    /// Real pessimistic proof inputs, taken from the proof requests of the SP1
    /// pessimistic proof program on the Succinct prover network. Certificates
    /// with an aggchain proof come with their real SP1 compressed proof.
    Network {
        /// Fetch these proof requests (0x-prefixed ids) instead of the latest.
        #[clap(long = "request-id")]
        request_ids: Vec<String>,

        /// Number of input files to write, from the latest fulfilled requests.
        /// Inputs already in the output directory count towards it and are not
        /// downloaded again, so an interrupted run can be resumed. Defaults to
        /// 10, or to no limit with `--per-kind`.
        #[clap(long)]
        limit: Option<usize>,

        /// Number of requests asked to the prover network per page.
        #[clap(long, default_value = "100")]
        page_size: u32,

        /// Only keep certificates of this kind. Can be repeated; defaults to
        /// all kinds.
        #[clap(long = "kind", value_enum)]
        kinds: Vec<Kind>,

        /// Stop once this many inputs of each kept kind are written. A kind
        /// the network has too few certificates of keeps the listing going
        /// until its end.
        #[clap(long)]
        per_kind: Option<usize>,

        /// Program vk hash (0x + 8 big-endian u32 words) of the SP1 pessimistic
        /// proof program to fetch requests for. Defaults to the one built by
        /// this repository.
        #[clap(long)]
        vk_hash: Option<String>,

        #[clap(long, default_value = SUCCINCT_RPC)]
        rpc: String,
    },

    /// A legacy ECDSA certificate built from the sample data, like `ppgen`.
    Sample {
        /// The number of bridge exits.
        #[clap(long, default_value = "10")]
        n_exits: usize,

        /// The number of imported bridge exits.
        #[clap(long, default_value = "10")]
        n_imported_exits: usize,
    },
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating {}", args.out_dir.display()))?;

    match args.source {
        Source::Network {
            request_ids,
            limit,
            page_size,
            kinds,
            per_kind,
            vk_hash,
            rpc,
        } => {
            // The SP1 client blocks, so the vk is computed outside the runtime.
            let vk_hash = match vk_hash {
                Some(vk_hash) => hex::decode(vk_hash.trim_start_matches("0x"))?,
                None => pp_vk_hash()?,
            };
            tokio::runtime::Runtime::new()?.block_on(network(
                &args.out_dir,
                &rpc,
                request_ids,
                Selection::new(kinds, per_kind, limit),
                page_size,
                vk_hash,
            ))
        }
        Source::Sample {
            n_exits,
            n_imported_exits,
        } => sample(&args.out_dir, n_exits, n_imported_exits),
    }
}

async fn network(
    out_dir: &Path,
    rpc_url: &str,
    request_ids: Vec<String>,
    mut selection: Selection,
    page_size: u32,
    vk_hash: Vec<u8>,
) -> eyre::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut rpc = ProverNetworkClient::connect(rpc_url.to_string()).await?;

    if !request_ids.is_empty() {
        for id in request_ids {
            let request_id = hex::decode(id.trim_start_matches("0x"))?;
            let request = rpc
                .get_proof_request_details(GetProofRequestDetailsRequest { request_id })
                .await?
                .into_inner()
                .request
                .ok_or_else(|| eyre!("unknown request {id}"))?;
            write_request(out_dir, &request, &mut selection).await;
        }
        return Ok(());
    }

    // Page through the latest fulfilled requests until the selection is
    // complete. Pages are numbered from 1; a page that brings no new request
    // ends the listing.
    let mut seen = HashSet::new();
    for page in 1.. {
        let requests = rpc
            .get_filtered_proof_requests(GetFilteredProofRequestsRequest {
                vk_hash: Some(vk_hash.clone()),
                fulfillment_status: Some(FulfillmentStatus::Fulfilled.into()),
                limit: Some(page_size),
                page: Some(page),
                ..Default::default()
            })
            .await?
            .into_inner()
            .requests;

        let mut new = 0;
        for request in requests {
            if !seen.insert(request.request_id.clone()) {
                continue;
            }
            new += 1;
            write_request(out_dir, &request, &mut selection).await;
            if selection.is_complete() {
                println!("{}", selection.summary());
                return Ok(());
            }
        }
        if new == 0 {
            break;
        }
    }
    println!("end of the listing: {}", selection.summary());
    Ok(())
}

/// Which certificates to keep, and how many are kept so far.
struct Selection {
    kinds: Vec<Kind>,
    per_kind: Option<usize>,
    limit: Option<usize>,
    written: BTreeMap<Kind, usize>,
}

impl Selection {
    fn new(kinds: Vec<Kind>, per_kind: Option<usize>, limit: Option<usize>) -> Self {
        let kinds = if kinds.is_empty() {
            Kind::ALL.to_vec()
        } else {
            kinds
        };
        let limit = limit.or(per_kind.is_none().then_some(10));
        Self {
            kinds,
            per_kind,
            limit,
            written: BTreeMap::new(),
        }
    }

    fn count(&self, kind: Kind) -> usize {
        self.written.get(&kind).copied().unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.written.values().sum()
    }

    /// Whether an input of `kind` is still wanted.
    fn wants(&self, kind: Kind) -> bool {
        self.kinds.contains(&kind) && self.per_kind.is_none_or(|n| self.count(kind) < n)
    }

    fn add(&mut self, kind: Kind) {
        *self.written.entry(kind).or_default() += 1;
    }

    fn is_complete(&self) -> bool {
        self.limit.is_some_and(|limit| self.total() >= limit)
            || self
                .per_kind
                .is_some_and(|n| self.kinds.iter().all(|&k| self.count(k) >= n))
    }

    fn summary(&self) -> String {
        let kinds: Vec<_> = self
            .kinds
            .iter()
            .map(|&kind| format!("{} {kind}", self.count(kind)))
            .collect();
        format!("{} inputs ({})", self.total(), kinds.join(", "))
    }
}

/// Writes the input of `request` if `selection` wants its kind, unless it is
/// already in `out_dir`, and counts it in `selection`. A request that cannot be
/// fetched or decoded is reported and skipped, so that one bad request does not
/// stop a long run.
async fn write_request(out_dir: &Path, request: &ProofRequest, selection: &mut Selection) {
    let id = format!("0x{}", hex::encode(&request.request_id));
    let path = out_dir.join(format!("{id}.bin"));
    if path.exists() {
        match read_witness(&path) {
            Ok((_, header)) => {
                let kind = Kind::of(&header);
                if selection.wants(kind) {
                    println!("{id}: already written, {kind}");
                    selection.add(kind);
                }
            }
            Err(error) => println!("{id}: skipped, unreadable {}: {error}", path.display()),
        }
        return;
    }
    if request.stdin_private || request.stdin_public_uri.is_empty() {
        println!("{id}: skipped, private stdin");
        return;
    }

    let fetched = async {
        let compressed = reqwest::get(&request.stdin_public_uri)
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let stdin: SP1Stdin = bincode1::deserialize(&zstd::decode_all(&compressed[..])?)?;
        eyre::Ok(stdin)
    }
    .await;
    let mut stdin = match fetched {
        Ok(stdin) => stdin,
        Err(error) => {
            println!("{id}: skipped, {error}");
            return;
        }
    };
    let state: NetworkState = stdin.read();
    let header: MultiBatchHeader = stdin.read();
    let kind = Kind::of(&header);
    if !selection.wants(kind) {
        return;
    }

    let input = ZiskStdin::new();
    input.write(&state);
    input.write(&header);
    for (proof, _) in &stdin.proofs {
        match pessimistic_proof::zisk::encode_sp1_compressed_proof(proof) {
            Ok(bytes) => input.write_slice(&bytes),
            Err(error) => {
                println!("{id}: skipped, {error}");
                return;
            }
        }
    }
    match save(out_dir, &id, &input, &state, &header, stdin.proofs.len()) {
        Ok(()) => selection.add(kind),
        Err(error) => println!("{id}: skipped, {error}"),
    }
}

fn sample(out_dir: &Path, n_exits: usize, n_imported_exits: usize) -> eyre::Result<()> {
    let events = |n| -> Vec<_> {
        data::sample_bridge_exits_01()
            .cycle()
            .take(n)
            .map(|exit| (exit.token_info, exit.amount))
            .collect()
    };

    let mut forest = data::sample_state_00();
    let state = forest.state_b.clone();
    let certificate = forest.apply_events(&events(n_imported_exits), &events(n_exits));
    let header = state.make_multi_batch_header(
        &certificate,
        L1WitnessCtx {
            l1_info_root: certificate.l1_info_root()?.unwrap_or_default(),
            prev_pessimistic_root: PessimisticRootInput::Computed(
                PessimisticRootCommitmentVersion::V2,
            ),
            aggchain_data_ctx: CertificateAggchainDataCtx::LegacyEcdsa {
                signer: forest.get_signer(),
            },
        },
    )?;
    let state = NetworkState::from(state);

    let input = ZiskStdin::new();
    input.write(&state);
    input.write(&header);
    let name = format!("sample-{n_exits}-exits-{n_imported_exits}-imported");
    save(out_dir, &name, &input, &state, &header, 0)
}

/// Writes `input` to `<out_dir>/<name>.bin` and reports what it contains.
/// The native execution does not verify aggchain proofs, so it only checks the
/// rest of the certificate.
fn save(
    out_dir: &Path,
    name: &str,
    input: &ZiskStdin,
    state: &NetworkState,
    header: &MultiBatchHeader,
    aggchain_proofs: usize,
) -> eyre::Result<()> {
    let path = out_dir.join(format!("{name}.bin"));
    input.save(&path)?;
    let native = match generate_pessimistic_proof(state.clone(), header) {
        Ok(_) => "accepted".to_string(),
        Err(error) => format!("rejected ({error})"),
    };
    println!(
        "{}: {}, network {}, {} bridge exits, {} imported bridge exits, {} SP1 aggchain proof(s), \
         native execution {native}",
        path.display(),
        Kind::of(header),
        header.origin_network,
        header.bridge_exits.len(),
        header.imported_bridge_exits.len(),
        aggchain_proofs,
    );
    Ok(())
}

/// Program vk hash of the SP1 pessimistic proof program, as the prover network
/// records it: its 8 vk hash words, big-endian.
fn pp_vk_hash() -> eyre::Result<Vec<u8>> {
    let vk = Runner::new().get_vkey()?;
    Ok(vk
        .hash_u32()
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect())
}
