//! [`FilterIter`].

use core::fmt;

use bdk_core::bitcoin;
use bdk_core::collections::{BTreeMap, BTreeSet};
use bdk_core::{BlockId, CheckPoint};
use bitcoin::{
    Block, BlockHash, ScriptBuf,
    bip158::{self, BlockFilter},
    block::Header,
};
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;

/// Type that return Bitcoin blocks by matching a list of script pubkeys (SPKs) against a
/// [`bip158::BlockFilter`].
///
/// ## Note
///
/// - You must add spks to `FilterIter` by using [`add_spks`]. If not you will get an
///   error when calling `next`. This is because [`match_any`] will be true for every
///   query, which is usually not what you want.
/// - Call `next` on the iterator to get the next [`Event`]. It is common to iterate
///   `FilterIter` [`by_ref`], so that you can continue to call methods on it.
/// - Use [`get_tip`] to find the tip of the remote node and to set the stop height.
/// - Iteration stops when filters for all heights have been scanned.
///
/// [`add_spks`]: Self::add_spks
/// [`match_any`]: BlockFilter::match_any
/// [`get_tip`]: Self::get_tip
/// [`by_ref`]: Self::by_ref
#[derive(Debug)]
pub struct FilterIter<'a> {
    /// RPC client
    client: &'a Client,
    /// SPKs to be used to match filters
    spks: Vec<ScriptBuf>,
    /// Block headers
    headers: BTreeMap<u32, (BlockHash, Header)>,
    /// Heights of matching blocks
    matched: BTreeSet<u32>,

    /// Initial height
    start: u32,
    /// Next height
    height: u32,
    /// Stop height
    stop: u32,
}

impl<'a> FilterIter<'a> {
    /// Hard cap on how far to walk back when a reorg is detected.
    const MAX_REORG_DEPTH: u32 = 100;
    /// The number of recent blocks that we always include in a chain update.
    const CHAIN_SUFFIX_LEN: u32 = 10;

    /// Construct [`FilterIter`] from a given `client` and start `height`.
    pub fn new_with_height(client: &'a Client, height: u32) -> Self {
        Self {
            client,
            spks: vec![],
            headers: BTreeMap::new(),
            matched: BTreeSet::new(),
            start: height,
            height,
            stop: 0,
        }
    }

    /// Construct [`FilterIter`] from a given `client` and [`CheckPoint`].
    ///
    /// # Errors
    ///
    /// If no point of agreement is found between `cp` and the remote node, then
    /// a [`Error::ReorgDepthExceeded`] error is returned.
    pub fn new_with_checkpoint(client: &'a Client, cp: CheckPoint) -> Result<Self, Error> {
        let mut iter = Self::new_with_height(client, cp.height());

        // Start scanning from `PoA` + 1.
        let base = iter.find_base(cp.clone())?;
        iter.height = base.height.saturating_add(1);

        Ok(iter)
    }

    /// Extends `self` with an iterator of spks.
    pub fn add_spks(&mut self, spks: impl IntoIterator<Item = ScriptBuf>) {
        self.spks.extend(spks);
    }

    /// Add spk to the list of spks to scan with.
    pub fn add_spk(&mut self, spk: ScriptBuf) {
        self.spks.push(spk);
    }

    /// Get the remote tip.
    ///
    /// This will set the stop height to the height of the new tip.
    ///
    /// Returns `None` if the remote height is not at least the height of this [`FilterIter`].
    pub fn get_tip(&mut self) -> Result<Option<BlockId>, Error> {
        let tip_hash = self.client.get_best_block_hash()?;
        let header = self.client.get_block_header_info(&tip_hash)?;
        let tip_height = header.height as u32;
        if self.height > tip_height {
            return Ok(None);
        }

        self.stop = tip_height;

        Ok(Some(BlockId {
            height: tip_height,
            hash: tip_hash,
        }))
    }

    /// Return all of the block headers that were collected during the scan.
    pub fn headers(&self) -> &BTreeMap<u32, (BlockHash, Header)> {
        &self.headers
    }
}

/// Event inner type
#[derive(Debug, Clone)]
pub struct EventInner {
    /// Height
    pub height: u32,
    /// Block
    pub block: Block,
}

/// Kind of event produced by [`FilterIter`].
#[derive(Debug, Clone)]
pub enum Event {
    /// Block
    Block(EventInner),
    /// No match
    NoMatch(u32),
}

impl Event {
    /// Whether this event contains a matching block.
    pub fn is_match(&self) -> bool {
        matches!(self, Event::Block(..))
    }

    /// Get the height of this event.
    pub fn height(&self) -> u32 {
        match self {
            Self::Block(EventInner { height, .. }) => *height,
            Self::NoMatch(h) => *h,
        }
    }
}

impl Iterator for FilterIter<'_> {
    type Item = Result<Event, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (|| -> Result<Option<_>, Error> {
            if self.height > self.stop {
                return Ok(None);
            }
            // Fetch next header.
            let mut height = self.height;
            let mut hash = self.client.get_block_hash(height as u64)?;

            let mut reorg_depth = 0;

            let header = loop {
                if reorg_depth >= Self::MAX_REORG_DEPTH {
                    return Err(Error::ReorgDepthExceeded);
                }

                let header = self.client.get_block_header(&hash)?;

                match height
                    .checked_sub(1)
                    .and_then(|prev_height| self.headers.get(&prev_height).copied())
                {
                    // Not enough data.
                    None => break header,
                    // Ok, the chain is consistent.
                    Some((prev_hash, _)) if prev_hash == header.prev_blockhash => break header,
                    _ => {
                        // Reorg detected, keep backtracking.
                        height = height.saturating_sub(1);
                        hash = self.client.get_block_hash(height as u64)?;
                        reorg_depth += 1;
                    }
                }
            };

            let filter_bytes = self.client.get_block_filter(&hash)?.filter;
            let filter = BlockFilter::new(&filter_bytes);

            // If the filter matches any of our watched SPKs, fetch the full
            // block and prepare the next event.
            let next_event = if self.spks.is_empty() {
                Err(Error::NoScripts)
            } else if filter
                .match_any(&hash, self.spks.iter().map(|s| s.as_bytes()))
                .map_err(Error::Bip158)?
            {
                let block = self.client.get_block(&hash)?;
                let inner = EventInner { height, block };
                Ok(Some(Event::Block(inner)))
            } else {
                Ok(Some(Event::NoMatch(height)))
            };

            // In case of a reorg, throw out any stale entries.
            if reorg_depth > 0 {
                self.headers.split_off(&height);
                self.matched.split_off(&height);
            }
            // Record the scanned block
            self.headers.insert(height, (hash, header));
            // Record the matching block
            if let Ok(Some(Event::Block(..))) = next_event {
                self.matched.insert(height);
            }
            // Increment next height
            self.height = height.saturating_add(1);

            next_event
        })()
        .transpose()
    }
}

impl FilterIter<'_> {
    /// Returns the point of agreement (`PoA`) between `self` and the given `cp`.
    ///
    /// This ensures that the scan may proceed from a block that still exists
    /// in the best chain. **Note: the [`Self::chain_update`] function relies on the assumption
    /// that the `PoA` block is represented in `self.headers`**, and this function is responsible
    /// for inserting it.
    ///
    /// If no `PoA` is found between `cp` and the remote node, then a [`Error::ReorgDepthExceeded`]
    /// error is returned.
    fn find_base(&mut self, mut cp: CheckPoint) -> Result<BlockId, Error> {
        loop {
            let height = cp.height();
            let (fetched_hash, header) = match self.headers.get(&height).copied() {
                Some(value) => value,
                None => {
                    let hash = self.client.get_block_hash(height as u64)?;
                    let header = self.client.get_block_header(&hash)?;
                    (hash, header)
                }
            };
            if cp.hash() == fetched_hash {
                self.headers.insert(height, (fetched_hash, header));
                return Ok(cp.block_id());
            }
            cp = cp.prev().ok_or(Error::ReorgDepthExceeded)?;
        }
    }

    /// Returns a chain update from the newly scanned blocks.
    ///
    /// This should only be called once all events have been consumed (by calling `next`).
    ///
    /// Returns `None` if the height of this `FilterIter` is not yet past the stop height.
    pub fn chain_update(&self) -> Option<CheckPoint> {
        if self.headers.is_empty() || self.height <= self.stop {
            return None;
        }

        // We return blocks up to the initial height, all of the matching blocks,
        // and blocks in the terminal range.
        let tail_range = (self.stop + 1).saturating_sub(Self::CHAIN_SUFFIX_LEN)..=self.stop;

        Some(
            CheckPoint::from_block_ids(self.headers.iter().filter_map(|(&height, &(hash, _))| {
                if height <= self.start
                    || self.matched.contains(&height)
                    || tail_range.contains(&height)
                {
                    Some(BlockId { height, hash })
                } else {
                    None
                }
            }))
            .expect("blocks must be in order"),
        )
    }
}

/// Errors that may occur during a compact filters sync.
#[derive(Debug)]
pub enum Error {
    /// bitcoin bip158 error
    Bip158(bip158::Error),
    /// attempted to scan blocks without any script pubkeys
    NoScripts,
    /// `bitcoincore_rpc` error
    Rpc(bitcoincore_rpc::Error),
    /// `MAX_REORG_DEPTH` exceeded
    ReorgDepthExceeded,
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        Self::Rpc(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bip158(e) => e.fmt(f),
            Self::NoScripts => write!(f, "no script pubkeys were provided to match with"),
            Self::Rpc(e) => e.fmt(f),
            Self::ReorgDepthExceeded => write!(f, "maximum reorg depth exceeded"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod test {
    use super::*;

    use bdk_core::{BlockId, CheckPoint};
    use bdk_testenv::{TestEnv, anyhow, bitcoind, block_id};
    use bitcoin::{Address, Amount, Network, ScriptBuf, constants};
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

    // Test the result of `chain_update` given a local checkpoint.
    //
    // new blocks
    //       2--3--4--5--6--7--8--9--10--11
    //
    // case 1: base below new blocks
    // 0-
    // case 2: base overlaps with new blocks
    // 0--1--2--3--4
    // case 3: stale tip (with overlap)
    // 0--1--2--3--4--x
    // case 4: stale tip (no overlap)
    // 0--x
    #[test]
    fn get_tip_and_chain_update() -> anyhow::Result<()> {
        let env = testenv()?;

        let genesis_hash = constants::genesis_block(Network::Regtest).block_hash();
        let genesis = BlockId {
            height: 0,
            hash: genesis_hash,
        };

        let hash = env.rpc_client().get_best_block_hash()?;
        let header = env.rpc_client().get_block_header_info(&hash)?;
        assert_eq!(header.height, 1);
        let block_1 = BlockId {
            height: header.height as u32,
            hash,
        };

        // `FilterIter` will try to return up to ten recent blocks
        // so we keep them for reference
        let new_blocks: Vec<BlockId> =
            (2..12).zip(env.mine_blocks(10, None)?).map(BlockId::from).collect();

        let new_tip = *new_blocks.last().unwrap();

        struct TestCase {
            // name
            name: &'static str,
            // local blocks
            chain: Vec<BlockId>,
            // expected blocks
            exp: Vec<BlockId>,
        }

        // For each test we create a new `FilterIter` with the checkpoint given
        // by the blocks in the test chain. Then we sync to the remote tip and
        // check the blocks that are returned in the chain update.
        [
            TestCase {
                name: "point of agreement below new blocks, expect base + new",
                chain: vec![genesis, block_1],
                exp: [block_1].into_iter().chain(new_blocks.clone()).collect(),
            },
            TestCase {
                name: "point of agreement genesis, expect base + new",
                chain: vec![genesis],
                exp: [genesis].into_iter().chain(new_blocks.clone()).collect(),
            },
            TestCase {
                name: "point of agreement within new blocks, expect base + remaining",
                chain: new_blocks[..=2].to_vec(),
                exp: new_blocks[2..].to_vec(),
            },
            TestCase {
                name: "stale tip within new blocks, expect base + corrected + remaining",
                // base height: 4, stale height: 5
                chain: vec![new_blocks[2], block_id!(5, "E")],
                exp: new_blocks[2..].to_vec(),
            },
            TestCase {
                name: "stale tip below new blocks, expect base + corrected + new",
                chain: vec![genesis, block_id!(1, "A")],
                exp: [genesis, block_1].into_iter().chain(new_blocks).collect(),
            },
        ]
        .into_iter()
        .for_each(|test| {
            let cp = CheckPoint::from_block_ids(test.chain).unwrap();
            let mut iter = FilterIter::new_with_checkpoint(&env.bitcoind.client, cp).unwrap();
            assert_eq!(iter.get_tip().unwrap(), Some(new_tip));
            for _res in iter.by_ref() {}
            let update_cp = iter.chain_update().unwrap();
            let mut update_blocks: Vec<_> = update_cp.iter().map(|cp| cp.block_id()).collect();
            update_blocks.reverse();
            assert_eq!(update_blocks, test.exp, "{}", test.name);
        });

        Ok(())
    }

    #[test]
    fn filter_iter_matches_blocks() -> anyhow::Result<()> {
        let env = testenv()?;
        let addr = env.rpc_client().get_new_address(None, None)?.assume_checked();

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

        let mut iter = FilterIter::new_with_height(&env.bitcoind.client, 1);
        assert_eq!(iter.get_tip()?.unwrap().height, 102);

        // Iterate events with no SPKs, expect none to match.
        for res in iter.by_ref().take(3) {
            match res {
                Err(..) => {}
                Ok(event) => {
                    assert!(!event.is_match());
                }
            }
        }

        assert!(iter.matched.is_empty());

        // Now add spks
        iter.add_spk(addr.script_pubkey());

        for res in iter.by_ref() {
            let event = res?;
            match event.height() {
                h if h <= 101 => {
                    assert!(event.is_match(), "we mined blocks to `addr`");
                }
                h if h == 102 => {
                    assert!(!event.is_match(), "_txid is not relevant to `addr`");
                }
                _ => unreachable!("we stopped at height 102"),
            }
        }

        // Range of matching heights [4, 101]
        assert_eq!(iter.matched, (4..=101).into_iter().collect::<BTreeSet<_>>());

        Ok(())
    }

    #[test]
    fn filter_iter_error_no_scripts() -> anyhow::Result<()> {
        let env = testenv()?;
        let _ = env.mine_blocks(2, None)?;

        let mut iter = FilterIter::new_with_height(&env.bitcoind.client, 1);
        assert_eq!(iter.get_tip()?.unwrap().height, 3);

        // iterator should return three errors
        for _ in 0..3 {
            assert!(matches!(iter.next().unwrap(), Err(Error::NoScripts)));
        }
        assert!(iter.next().is_none());

        Ok(())
    }

    // Test that while a reorg is detected we delay incrementing the best height
    #[test]
    fn repeat_reorgs() -> anyhow::Result<()> {
        const MINE_TO: u32 = 16;

        let env = testenv()?;
        let rpc = env.rpc_client();
        while rpc.get_block_count()? < MINE_TO as u64 {
            let _ = env.mine_blocks(1, None)?;
        }

        let spk = ScriptBuf::from_hex("0014446906a6560d8ad760db3156706e72e171f3a2aa")?;

        let mut iter = FilterIter::new_with_height(&env.bitcoind.client, 1);
        iter.add_spk(spk);
        assert_eq!(iter.get_tip()?.unwrap().height, MINE_TO);

        // Process events to height (MINE_TO - 1)
        loop {
            if iter.next().unwrap()?.height() == MINE_TO - 1 {
                break;
            }
        }

        for _ in 0..3 {
            // Invalidate 2 blocks and remine to height = MINE_TO
            let _ = env.reorg(2)?;

            // Call next. If we detect a reorg, we'll see no change in the event height
            assert_eq!(iter.next().unwrap()?.height(), MINE_TO - 1);
        }

        // If no reorg, then height should increment normally from here on
        assert_eq!(iter.next().unwrap()?.height(), MINE_TO);
        assert!(iter.next().is_none());

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
        let err = FilterIter::new_with_checkpoint(&env.bitcoind.client, cp).unwrap_err();
        assert!(matches!(err, Error::ReorgDepthExceeded));

        Ok(())
    }

    #[test]
    fn filter_iter_max_reorg_depth() -> anyhow::Result<()> {
        let env = testenv()?;

        const BASE_HEIGHT: u32 = 10;
        const REORG_LEN: u32 = 101;
        const STOP_HEIGHT: u32 = BASE_HEIGHT + REORG_LEN;

        while env.rpc_client().get_block_count()? < STOP_HEIGHT as u64 {
            env.mine_blocks(1, None)?;
        }

        let mut iter = FilterIter::new_with_height(&env.bitcoind.client, BASE_HEIGHT);
        let spk = ScriptBuf::from_hex("0014446906a6560d8ad760db3156706e72e171f3a2aa")?;
        iter.add_spk(spk.clone());
        assert_eq!(iter.get_tip()?.unwrap().height, STOP_HEIGHT);

        // Consume events up to STOP_HEIGHT - 1.
        loop {
            if iter.next().unwrap()?.height() == STOP_HEIGHT - 1 {
                break;
            }
        }

        let _ = env.reorg(REORG_LEN as usize)?;

        assert!(matches!(iter.next(), Some(Err(Error::ReorgDepthExceeded))));

        Ok(())
    }
}
