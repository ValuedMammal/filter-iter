//! [`FilterIter`].

use alloc::vec::Vec;

use bdk_core::{BlockId, CheckPoint};
use bitcoin::bip158::BlockFilter;
use bitcoin::{Block, ScriptBuf};

use bitcoincore_rpc::{json::GetBlockHeaderResult, RpcApi};

/// Filter iter.
#[derive(Debug)]
pub struct FilterIter<'a> {
    /// RPC client
    client: &'a bitcoincore_rpc::Client,
    /// SPK inventory
    spks: Vec<ScriptBuf>,
    /// checkpoint
    cp: CheckPoint,
    /// Header info, contains the prev and next hashes for each header.
    header: Option<GetBlockHeaderResult>,
}

impl<'a> FilterIter<'a> {
    /// Construct [`FilterIter`] with checkpoint, RPC client and SPKs.
    pub fn new(
        client: &'a bitcoincore_rpc::Client,
        cp: CheckPoint,
        spks: impl IntoIterator<Item = ScriptBuf>,
    ) -> Self {
        Self {
            client,
            spks: spks.into_iter().collect(),
            cp,
            header: None,
        }
    }

    /// Find the agreement height with the remote node and return the corresponding
    /// header info.
    ///
    /// Error if no point of agreement is found.
    fn find_base(&self) -> Result<GetBlockHeaderResult, Error> {
        for cp in self.cp.iter() {
            let height = cp.height();

            let fetched_hash = self.client.get_block_hash(height as u64)?;

            if fetched_hash == cp.hash() {
                let header = self.client.get_block_header_info(&fetched_hash)?;
                return Ok(header);
            }
        }

        Err(Error::ReorgDepthExceeded)
    }
}

/// Kind of event produced by `FilterIter`.
#[derive(Debug, Clone)]
pub enum Event {
    /// Block
    Block {
        /// checkpoint
        cp: CheckPoint,
        /// block
        block: Block,
    },
    /// No match
    NoMatch {
        /// block id
        id: BlockId,
    },
    /// Tip
    Tip {
        /// checkpoint
        cp: CheckPoint,
    },
}

impl Event {
    /// Whether this event contains a matching block.
    pub fn is_match(&self) -> bool {
        matches!(self, Event::Block { .. })
    }

    /// Return the height of the event.
    pub fn height(&self) -> u32 {
        match self {
            Self::Block { cp, .. } | Self::Tip { cp } => cp.height(),
            Self::NoMatch { id } => id.height,
        }
    }
}

impl Iterator for FilterIter<'_> {
    type Item = Result<Event, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (|| -> Result<Option<_>, Error> {
            let mut cp = self.cp.clone();

            let header = match self.header.take() {
                Some(header) => header,
                None => {
                    // If no header is cached we need to locate a base of the local
                    // checkpoint from which the scan may proceed.
                    let header = self.find_base()?;
                    let height: u32 = header.height.try_into().unwrap();
                    cp = cp.range(..=height).next().unwrap();

                    header
                }
            };

            let Some(next_hash) = header.next_block_hash else {
                return Ok(None);
            };

            let mut next_header = self.client.get_block_header_info(&next_hash)?;

            // In case of a reorg, rewind by fetching headers of previous hashes until we find
            // one with enough confirmations.
            let mut reorg_ct: i32 = 0;
            while next_header.confirmations < 0 {
                let prev_hash = next_header
                    .previous_block_hash
                    .ok_or(Error::ReorgDepthExceeded)?;
                let prev_header = self.client.get_block_header_info(&prev_hash)?;
                next_header = prev_header;
                reorg_ct += 1;
            }

            let next_height: u32 = next_header.height.try_into().unwrap();

            // Purge any no longer valid checkpoints.
            if reorg_ct.is_positive() {
                cp = cp.range(..=next_height).next().unwrap();
            }
            let block_id = BlockId {
                height: next_height,
                hash: next_hash,
            };
            let filter_bytes = self.client.get_block_filter(&next_hash)?.filter;
            let filter = BlockFilter::new(&filter_bytes);

            let next_event = if filter
                .match_any(&next_hash, self.spks.iter().map(ScriptBuf::as_ref))
                .map_err(Error::Bip158)?
            {
                let block = self.client.get_block(&next_hash)?;
                cp = cp.insert(block_id);

                Ok(Some(Event::Block {
                    cp: cp.clone(),
                    block,
                }))
            } else if next_header.next_block_hash.is_none() {
                cp = cp.insert(block_id);

                Ok(Some(Event::Tip { cp: cp.clone() }))
            } else {
                Ok(Some(Event::NoMatch { id: block_id }))
            };

            // Store the next header
            self.header = Some(next_header);
            // Update self.cp
            self.cp = cp;

            next_event
        })()
        .transpose()
    }
}

/// Error
#[derive(Debug)]
pub enum Error {
    /// RPC error
    Rpc(bitcoincore_rpc::Error),
    /// `bitcoin::bip158` error
    Bip158(bitcoin::bip158::Error),
    /// Max reorg depth exceeded.
    ReorgDepthExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => write!(f, "{e}"),
            Self::Bip158(e) => write!(f, "{e}"),
            Self::ReorgDepthExceeded => write!(f, "maximum reorg depth exceeded"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        Self::Rpc(e)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bdk_core::{BlockId, CheckPoint};
    use bdk_testenv::{anyhow, bitcoind, TestEnv};
    use bitcoin::{Address, Amount, Network, ScriptBuf};
    use bitcoincore_rpc::RpcApi;

    fn testenv() -> anyhow::Result<TestEnv> {
        let mut conf = bitcoind::Conf::default();
        conf.args.push("-blockfilterindex=1");
        conf.args.push("-peerblockfilters=1");
        TestEnv::new_with_config(bdk_testenv::Config {
            bitcoind: conf,
            ..Default::default()
        })
    }

    #[test]
    fn filter_iter_matches_blocks() -> anyhow::Result<()> {
        let env = testenv()?;
        let addr = env
            .rpc_client()
            .get_new_address(None, None)?
            .assume_checked();

        let _ = env.mine_blocks(100, Some(addr.clone()))?;
        assert_eq!(env.rpc_client().get_block_count()?, 101);

        // Send tx to external address to confirm at height = 102
        let _txid = env.send(
            &Address::from_script(
                &ScriptBuf::from_hex("0014446906a6560d8ad760db3156706e72e171f3a2aa")?,
                Network::Regtest,
            )?,
            Amount::from_btc(0.42)?,
        )?;
        let _ = env.mine_blocks(1, None);

        let genesis_hash = env.genesis_hash()?;
        let cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis_hash,
        });

        let iter = FilterIter::new(&env.bitcoind.client, cp, vec![addr.script_pubkey()]);

        for res in iter {
            let event = res?;
            let height = event.height();
            if (2..102).contains(&height) {
                assert!(event.is_match(), "expected to match height {height}");
            }
        }

        Ok(())
    }

    #[test]
    fn filter_iter_error_wrong_network() -> anyhow::Result<()> {
        let env = testenv()?;
        let _ = env.mine_blocks(10, None)?;

        // Try to initialize FilterIter with a CP on the wrong network
        let block_id = BlockId {
            height: 0,
            hash: bitcoin::hashes::Hash::hash(b"wrong-hash"),
        };
        let cp = CheckPoint::new(block_id);
        let mut iter = FilterIter::new(&env.bitcoind.client, cp, vec![ScriptBuf::new()]);
        assert!(matches!(iter.next(), Some(Err(Error::ReorgDepthExceeded))));

        Ok(())
    }

    // Test that while a reorg is detected we delay incrementing the best height
    #[test]
    fn filter_iter_detects_reorgs() -> anyhow::Result<()> {
        const MINE_TO: u32 = 16;

        let env = testenv()?;
        let rpc = env.rpc_client();
        while rpc.get_block_count()? < MINE_TO as u64 {
            let _ = env.mine_blocks(1, None)?;
        }

        let genesis_hash = env.genesis_hash()?;
        let cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis_hash,
        });

        let spk = ScriptBuf::from_hex("0014446906a6560d8ad760db3156706e72e171f3a2aa")?;
        let mut iter = FilterIter::new(&env.bitcoind.client, cp, vec![spk]);

        // Process events to height (MINE_TO - 1)
        loop {
            if iter.next().unwrap()?.height() == MINE_TO - 1 {
                break;
            }
        }

        for _ in 0..3 {
            // Invalidate and remine 1 block
            let _ = env.reorg(1)?;

            // Call next. If we detect a reorg, we'll see no change in the event height
            assert_eq!(iter.next().unwrap()?.height(), MINE_TO - 1);
        }

        // If no reorg, then height should increment normally from here on
        assert_eq!(iter.next().unwrap()?.height(), MINE_TO);
        assert!(iter.next().is_none());

        Ok(())
    }
}
