use std::time::Instant;

use filter_iter::{Event, EventInner, FilterIter};

use anyhow::Context;
use bdk_chain::bitcoin::{Network, constants::genesis_block, secp256k1::Secp256k1};
use bdk_chain::indexer::keychain_txout::KeychainTxOutIndex;
use bdk_chain::local_chain::LocalChain;
use bdk_chain::miniscript::Descriptor;
use bdk_chain::{BlockId, ConfirmationBlockTime, IndexedTxGraph, SpkIterator};
use bdk_testenv::anyhow;

// This example shows how BDK chain and tx-graph structures are updated using compact
// filters syncing. Assumes a connection can be made to a bitcoin node via environment
// variables `RPC_URL` and `RPC_COOKIE`.

// Usage: `cargo run -p bdk_bitcoind_rpc --example filter_iter`

const EXTERNAL: &str = "tr(tprv8ZgxMBicQKsPczwfSDDHGpmNeWzKaMajLtkkNUdBoisixK3sW3YTC8subMCsTJB7sM4kaJJ7K1cNVM37aZoJ7dMBt2HRYLQzoFPqPMC8cTr/86'/1'/0'/0/*)";
const INTERNAL: &str = "tr(tprv8ZgxMBicQKsPczwfSDDHGpmNeWzKaMajLtkkNUdBoisixK3sW3YTC8subMCsTJB7sM4kaJJ7K1cNVM37aZoJ7dMBt2HRYLQzoFPqPMC8cTr/86'/1'/0'/1/*)";
const SPK_COUNT: u32 = 25;
const NETWORK: Network = Network::Signet;

const START_HEIGHT: u32 = 205_000;
const START_HASH: &str = "0000002bd0f82f8c0c0f1e19128f84c938763641dba85c44bdb6aed1678d16cb";

fn main() -> anyhow::Result<()> {
    // Setup receiving chain and graph structures.
    let secp = Secp256k1::new();
    let (descriptor, _) = Descriptor::parse_descriptor(&secp, EXTERNAL)?;
    let (change_descriptor, _) = Descriptor::parse_descriptor(&secp, INTERNAL)?;
    let (mut chain, _) = LocalChain::from_genesis_hash(genesis_block(NETWORK).block_hash());

    let mut graph = IndexedTxGraph::<ConfirmationBlockTime, KeychainTxOutIndex<&str>>::new({
        let mut index = KeychainTxOutIndex::default();
        index.insert_descriptor("external", descriptor.clone())?;
        index.insert_descriptor("internal", change_descriptor.clone())?;
        index
    });

    // Assume a minimum birthday height
    let block = BlockId {
        height: START_HEIGHT,
        hash: START_HASH.parse()?,
    };
    let _ = chain.insert_block(block)?;

    // Configure RPC client
    let url = std::env::var("RPC_URL").context("must set RPC_URL")?;
    let cookie = std::env::var("RPC_COOKIE").context("must set RPC_COOKIE")?;
    let rpc_client =
        bitcoincore_rpc::Client::new(&url, bitcoincore_rpc::Auth::CookieFile(cookie.into()))?;

    // Initialize FilterIter
    let cp = chain.tip();
    let start_height = cp.height();
    let mut iter = FilterIter::new_with_checkpoint(&rpc_client, cp)?;
    for (_, desc) in graph.index.keychains() {
        let spks = SpkIterator::new_with_range(desc, 0..SPK_COUNT).map(|(_, spk)| spk);
        iter.add_spks(spks);
    }

    let start = Instant::now();

    // Sync
    if let Some(tip) = iter.get_tip()? {
        let blocks_to_scan = tip.height - start_height;

        for event in iter.by_ref() {
            let event = event?;
            let curr = event.height();
            // apply relevant blocks
            if let Event::Block(EventInner { height, ref block }) = event {
                let _ = graph.apply_block_relevant(block, height);
                println!("Matched block {curr}");
            }
            if curr % 1000 == 0 {
                let progress = (curr - start_height) as f32 / blocks_to_scan as f32;
                println!("[{:.2}%]", progress * 100.0);
            }
        }
        // update chain
        if let Some(cp) = iter.chain_update() {
            let _ = chain.apply_update(cp)?;
        }
    }

    for canon_tx in graph.graph().list_canonical_txs(
        &chain,
        chain.tip().block_id(),
        bdk_chain::CanonicalizationParams::default(),
    ) {
        if !canon_tx.chain_position.is_confirmed() {
            eprintln!("ERROR: expected canonical txs to be confirmed");
        }
    }

    println!("\ntook: {}s", start.elapsed().as_secs());
    println!("Local tip: {}", chain.tip().height());
    let unspent: Vec<_> = graph
        .graph()
        .filter_chain_unspents(
            &chain,
            chain.tip().block_id(),
            Default::default(),
            graph.index.outpoints().clone(),
        )
        .collect();
    if !unspent.is_empty() {
        println!("\nUnspent");
        for (index, utxo) in unspent {
            // (k, index) | value | outpoint |
            println!("{:?} | {} | {}", index, utxo.txout.value, utxo.outpoint);
        }
    }

    Ok(())
}
