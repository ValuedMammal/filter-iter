use alloc::vec::Vec;

use bdk_core::bitcoin;
use bdk_core::{BlockId, CheckPoint};
use bitcoin::{bip158::BlockFilter, Block, ScriptBuf};
use bitcoincore_rpc::{json::GetBlockHeaderResult, RpcApi};

/// Type that returns Bitcoin blocks by matching a list of script pubkeys (SPKs) against a
/// [`bip158::BlockFilter`].
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

    /// Return the agreement header with the remote node.
    ///
    /// Error if no agreement header is found.
    fn find_base(&self) -> Result<GetBlockHeaderResult, Error> {
        for cp in self.cp.iter() {
            match self.client.get_block_header_info(&cp.hash()) {
                Err(e) if is_not_found(&e) => continue,
                Ok(header) if header.confirmations <= 0 => continue,
                Ok(header) => return Ok(header),
                Err(e) => return Err(Error::Rpc(e)),
            }
        }
        Err(Error::ReorgDepthExceeded)
    }
}

/// Event returned by [`FilterIter`].
#[derive(Debug, Clone)]
pub struct Event {
    /// Checkpoint
    pub cp: CheckPoint,
    /// Block, will be `Some(..)` for matching blocks
    pub block: Option<Block>,
}

impl Event {
    /// Whether this event contains a matching block.
    pub fn is_match(&self) -> bool {
        self.block.is_some()
    }

    /// Return the height of the event.
    pub fn height(&self) -> u32 {
        self.cp.height()
    }
}

impl Iterator for FilterIter<'_> {
    type Item = Result<Event, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (|| -> Result<Option<_>, Error> {
            let mut cp = self.cp.clone();

            let header = match self.header.take() {
                Some(header) => header,
                // If no header is cached we need to locate a base of the local
                // checkpoint from which the scan may proceed.
                None => self.find_base()?,
            };

            let mut next_hash = match header.next_block_hash {
                Some(hash) => hash,
                None => return Ok(None),
            };

            let mut next_header = self.client.get_block_header_info(&next_hash)?;

            // In case of a reorg, rewind by fetching headers of previous hashes until we find
            // one with enough confirmations.
            while next_header.confirmations < 0 {
                let prev_hash = next_header
                    .previous_block_hash
                    .ok_or(Error::ReorgDepthExceeded)?;
                let prev_header = self.client.get_block_header_info(&prev_hash)?;
                next_header = prev_header;
            }

            next_hash = next_header.hash;
            let next_height: u32 = next_header.height.try_into()?;

            cp = cp.insert(BlockId {
                height: next_height,
                hash: next_hash,
            });

            let mut block = None;
            let filter =
                BlockFilter::new(self.client.get_block_filter(&next_hash)?.filter.as_slice());
            if filter
                .match_any(&next_hash, self.spks.iter().map(ScriptBuf::as_ref))
                .map_err(Error::Bip158)?
            {
                block = Some(self.client.get_block(&next_hash)?);
            }

            // Store the next header
            self.header = Some(next_header);
            // Update self.cp
            self.cp = cp.clone();

            Ok(Some(Event { cp, block }))
        })()
        .transpose()
    }
}

/// Error that may be thrown by [`FilterIter`].
#[derive(Debug)]
pub enum Error {
    /// RPC error
    Rpc(bitcoincore_rpc::Error),
    /// `bitcoin::bip158` error
    Bip158(bitcoin::bip158::Error),
    /// Max reorg depth exceeded.
    ReorgDepthExceeded,
    /// Error converting an integer
    TryFromInt(core::num::TryFromIntError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => write!(f, "{e}"),
            Self::Bip158(e) => write!(f, "{e}"),
            Self::ReorgDepthExceeded => write!(f, "maximum reorg depth exceeded"),
            Self::TryFromInt(e) => write!(f, "{e}"),
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

impl From<core::num::TryFromIntError> for Error {
    fn from(e: core::num::TryFromIntError) -> Self {
        Self::TryFromInt(e)
    }
}

/// Whether the RPC error is a "not found" error (code: `-5`).
fn is_not_found(e: &bitcoincore_rpc::Error) -> bool {
    matches!(
        e,
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(e))
        if e.code == -5
    )
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
