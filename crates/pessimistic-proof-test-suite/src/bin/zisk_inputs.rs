//! Writes input files for the ZisK pessimistic proof program, to run with
//! `ziskemu -i` or `cargo-zisk execute/prove -i`.
//!
//! An input is the guest's stdin: the `NetworkState`, the `MultiBatchHeader`
//! and, if the certificate carries one, the SP1 compressed aggchain proof.

use std::path::{Path, PathBuf};

use agglayer_types::{
    aggchain_data::CertificateAggchainDataCtx, L1WitnessCtx, PessimisticRootInput,
};
use agglayer_zisk::ZiskStdin;
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

        /// Number of latest fulfilled requests to fetch.
        #[clap(long, default_value = "10")]
        limit: u32,

        /// Only keep certificates that carry an SP1 aggchain proof.
        #[clap(long)]
        aggchain_proof_only: bool,

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
            aggchain_proof_only,
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
                limit,
                aggchain_proof_only,
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
    limit: u32,
    aggchain_proof_only: bool,
    vk_hash: Vec<u8>,
) -> eyre::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut rpc = ProverNetworkClient::connect(rpc_url.to_string()).await?;

    let requests: Vec<ProofRequest> = if request_ids.is_empty() {
        rpc.get_filtered_proof_requests(GetFilteredProofRequestsRequest {
            vk_hash: Some(vk_hash),
            fulfillment_status: Some(FulfillmentStatus::Fulfilled.into()),
            limit: Some(limit),
            ..Default::default()
        })
        .await?
        .into_inner()
        .requests
    } else {
        let mut requests = Vec::new();
        for id in request_ids {
            let request_id = hex::decode(id.trim_start_matches("0x"))?;
            let details = rpc
                .get_proof_request_details(GetProofRequestDetailsRequest { request_id })
                .await?
                .into_inner();
            requests.push(
                details
                    .request
                    .ok_or_else(|| eyre!("unknown request {id}"))?,
            );
        }
        requests
    };

    for request in requests {
        let id = format!("0x{}", hex::encode(&request.request_id));
        if request.stdin_private || request.stdin_public_uri.is_empty() {
            println!("{id}: skipped, private stdin");
            continue;
        }

        let compressed = reqwest::get(&request.stdin_public_uri)
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let mut stdin: SP1Stdin = bincode1::deserialize(&zstd::decode_all(&compressed[..])?)?;
        let state: NetworkState = stdin.read();
        let header: MultiBatchHeader = stdin.read();
        if aggchain_proof_only && stdin.proofs.is_empty() {
            continue;
        }

        let input = ZiskStdin::new();
        input.write(&state);
        input.write(&header);
        for (proof, _) in &stdin.proofs {
            input.write_slice(&pessimistic_proof::zisk::encode_sp1_compressed_proof(
                proof,
            )?);
        }
        save(out_dir, &id, &input, &state, &header, stdin.proofs.len())?;
    }
    Ok(())
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
        "{}: network {}, {} bridge exits, {} imported bridge exits, {} SP1 aggchain proof(s), \
         native execution {native}",
        path.display(),
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
