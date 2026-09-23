use std::collections::{HashMap, HashSet};

use bitcoin::{Transaction, Txid, Wtxid};
use tokio::sync::oneshot;

use crate::{network::PeerId, Package};

#[derive(Debug)]
pub(crate) struct BroadcastQueue {
    // There are the transactions that a peer should receive first. In the case of 1p1c, these are
    // the `Wtxid` of the child transaction in the package.
    advertise: HashSet<Wtxid>,
    // Notify the user when:
    // 1. a singleton transaction was broadcast
    // 2. the final transaction in a package was broadcast
    callbacks: HashMap<Wtxid, (oneshot::Sender<Wtxid>, Wtxid)>,
    // These transactions will be fetched by the usual `Wtxid`.
    witness_data: HashMap<Wtxid, Transaction>,
    // These transactions represent missing inputs to a previously broadcast transaction. Because
    // the inputs use the legacy `Txid` in the outpoint, these transactions are indexed by `Txid`.
    legacy_data: HashMap<Txid, Transaction>,
    // Exact package payloads in dependency order. Submission flushes these
    // after the normal inventory announcement instead of depending solely on
    // remote getdata scheduling.
    packages: HashMap<Wtxid, Vec<Transaction>>,
    // A package remains globally visible until every peer that was active at
    // submission has received its immutable payload. Without this per-peer
    // delivery set, the first peer to flush a package removes it before the
    // other peer tasks necessarily get a chance to snapshot the queue.
    fanout_remaining: HashMap<Wtxid, HashSet<PeerId>>,
}

impl BroadcastQueue {
    pub(crate) fn new() -> Self {
        Self {
            advertise: HashSet::new(),
            callbacks: HashMap::new(),
            witness_data: HashMap::new(),
            legacy_data: HashMap::new(),
            packages: HashMap::new(),
            fanout_remaining: HashMap::new(),
        }
    }

    pub(crate) fn add_to_queue(
        &mut self,
        package: Package,
        oneshot: oneshot::Sender<Wtxid>,
        target_peers: impl IntoIterator<Item = PeerId>,
    ) {
        let advertise_wtxid = package.advertise_package();
        self.advertise.insert(advertise_wtxid);
        self.fanout_remaining
            .insert(advertise_wtxid, target_peers.into_iter().collect());
        let parent = package.parent();
        let parent_txid = parent.compute_txid();
        let parent_wtxid = parent.compute_wtxid();
        // Canonical txid inventory causes legacy or BIP339-capable peers to
        // request the payload by txid. Retain every package member under that
        // identifier as well as wtxid so the request can actually be served.
        // This is also required for singleton broadcasts and for the child we
        // advertise first in a 1p1c package.
        self.legacy_data.insert(parent_txid, parent.clone());
        match package.child() {
            Some(child) => {
                let child_txid = child.compute_txid();
                let child_wtxid = child.compute_wtxid();
                // Only confirm once the parent is confirmed to have been requested.
                self.callbacks.insert(parent_wtxid, (oneshot, child_wtxid));
                self.witness_data.insert(child_wtxid, child.clone());
                self.legacy_data.insert(child_txid, child.clone());
                self.packages.insert(advertise_wtxid, vec![parent, child]);
            }
            None => {
                self.callbacks.insert(parent_wtxid, (oneshot, parent_wtxid));
                self.witness_data.insert(parent_wtxid, parent.clone());
                self.packages.insert(advertise_wtxid, vec![parent]);
            }
        }
    }

    pub(crate) fn fetch_tx(&self, id: impl Into<TxIdentifier>) -> Option<Transaction> {
        let id = id.into();
        match id {
            TxIdentifier::Legacy(txid) => self.legacy_data.get(&txid).cloned(),
            TxIdentifier::Witness(wtxid) => self.witness_data.get(&wtxid).cloned(),
        }
    }

    pub(crate) fn sent_transaction_payload(&mut self, wtxid: Wtxid, peer: PeerId) {
        if let Some((_, advertised)) = self.callbacks.get(&wtxid) {
            self.record_peer_delivery(*advertised, peer);
        }
    }

    /// Snapshot pending packages for direct peer publication. Parents precede
    /// children so receivers can validate a 1p1c package without an orphan
    /// round trip.
    pub(crate) fn pending_packages(&self) -> Vec<(Wtxid, Vec<Transaction>)> {
        self.advertise
            .iter()
            .filter_map(|advertised| {
                self.packages
                    .get(advertised)
                    .cloned()
                    .map(|transactions| (*advertised, transactions))
            })
            .collect()
    }

    /// Record that one target peer received every exact payload in the queued
    /// package. Complete the submission only after every peer that was active
    /// when it was enqueued has received the package.
    pub(crate) fn sent_package_payload(&mut self, advertised_wtxid: Wtxid, peer: PeerId) {
        self.record_peer_delivery(advertised_wtxid, peer);
    }

    fn record_peer_delivery(&mut self, advertised_wtxid: Wtxid, peer: PeerId) {
        let Some(remaining) = self.fanout_remaining.get_mut(&advertised_wtxid) else {
            return;
        };
        if !remaining.remove(&peer) || !remaining.is_empty() {
            return;
        }
        self.fanout_remaining.remove(&advertised_wtxid);
        let completion = self
            .callbacks
            .iter()
            .find_map(|(completion, (_, advertised))| {
                (*advertised == advertised_wtxid).then_some(*completion)
            });
        if let Some(completion) = completion {
            if let Some((callback, advertised)) = self.callbacks.remove(&completion) {
                self.advertise.remove(&advertised);
                let _ = callback.send(advertised);
            }
        }
    }

    /// Return BIP339 inventory for every transaction awaiting delivery.
    ///
    /// Every admitted peer is protocol 70016 or newer and this client sends
    /// `wtxidrelay` during its version handshake. BIP339 therefore requires
    /// subsequent transaction announcements to use `MSG_WTX`.
    pub(crate) fn pending_wtxid(&self) -> Vec<Wtxid> {
        self.advertise.iter().copied().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash)]
pub(crate) enum TxIdentifier {
    Legacy(Txid),
    Witness(Wtxid),
}

impl From<Txid> for TxIdentifier {
    fn from(value: Txid) -> Self {
        Self::Legacy(value)
    }
}

impl From<Wtxid> for TxIdentifier {
    fn from(value: Wtxid) -> Self {
        Self::Witness(value)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use bitcoin::Transaction;
    use corepc_node::serde_json;

    use super::{BroadcastQueue, PeerId};

    #[derive(Debug, Clone)]
    struct HexTx(Transaction);
    crate::impl_deserialize!(HexTx, Transaction);

    #[derive(Debug, Clone, serde::Deserialize)]
    struct TransactionFile {
        transactions: Vec<HexTx>,
    }

    #[test]
    fn test_broadcast_queue_works() {
        // Sourced from BIP 174 test vectors
        let tx_file = File::open("./tests/data/transactions.json").unwrap();
        let tx_data: TransactionFile = serde_json::from_reader(&tx_file).unwrap();
        let transaction_1: Transaction = tx_data.transactions[0].clone().0;
        let transaction_2: Transaction = tx_data.transactions[1].clone().0;
        let mut queue = BroadcastQueue::new();
        let (tx, _) = tokio::sync::oneshot::channel();
        queue.add_to_queue(transaction_1.clone().into(), tx, [PeerId(1)]);
        let (tx, _) = tokio::sync::oneshot::channel();
        queue.add_to_queue(transaction_2.clone().into(), tx, [PeerId(1)]);
        assert_eq!(queue.pending_wtxid().len(), 2);
        assert_eq!(queue.pending_packages().len(), 2);
        assert_eq!(
            queue.fetch_tx(transaction_1.compute_txid()),
            Some(transaction_1.clone()),
        );
        assert_eq!(
            queue.fetch_tx(transaction_2.compute_txid()),
            Some(transaction_2.clone()),
        );
        queue.sent_transaction_payload(transaction_1.compute_wtxid(), PeerId(1));
        assert_eq!(queue.pending_wtxid(), vec![transaction_2.compute_wtxid()]);
        assert!(queue.fetch_tx(transaction_1.compute_wtxid()).is_some());
        assert!(queue.fetch_tx(transaction_2.compute_wtxid()).is_some());
        queue.sent_transaction_payload(transaction_2.compute_wtxid(), PeerId(1));
        assert!(queue.pending_wtxid().is_empty());

        let mut queue = BroadcastQueue::new();
        let (callback, receiver) = tokio::sync::oneshot::channel();
        queue.add_to_queue(
            transaction_1.clone().into(),
            callback,
            [PeerId(1), PeerId(2)],
        );
        queue.sent_package_payload(transaction_1.compute_wtxid(), PeerId(1));
        assert_eq!(queue.pending_wtxid(), vec![transaction_1.compute_wtxid()]);
        queue.sent_package_payload(transaction_1.compute_wtxid(), PeerId(2));
        assert_eq!(
            receiver.blocking_recv().unwrap(),
            transaction_1.compute_wtxid(),
        );
        assert!(queue.pending_wtxid().is_empty());
    }
}
