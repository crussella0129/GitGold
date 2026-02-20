use gitgold_core::error::LedgerError;
use gitgold_core::types::{Address, MicroGitGold, TransactionType};
use gitgold_crypto::hash::sha256_hex;
use gitgold_crypto::keys::PublicKey;
use rusqlite::Connection;
use std::collections::HashSet;

use crate::balance::BalanceTracker;
use crate::merkle::MerkleTree;
use crate::supply::SupplyTracker;
use crate::transaction::Transaction;

/// Append-only ledger backed by SQLite.
///
/// On open, replays all transactions to rebuild balances.
/// Merkle trees are built over transaction batches.
pub struct Ledger {
    conn: Connection,
    balances: BalanceTracker,
    supply: SupplyTracker,
    tx_ids: HashSet<String>,
}

impl Ledger {
    /// Open (or create) a ledger at the given path.
    pub fn open(path: &str) -> Result<Self, LedgerError> {
        let conn = Connection::open(path).map_err(|e| LedgerError::Database(e.to_string()))?;
        Self::init(conn)
    }

    /// Create an in-memory ledger (for tests).
    pub fn in_memory() -> Result<Self, LedgerError> {
        let conn =
            Connection::open_in_memory().map_err(|e| LedgerError::Database(e.to_string()))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, LedgerError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS transactions (
                tx_id       TEXT PRIMARY KEY,
                tx_type     TEXT NOT NULL,
                from_addr   TEXT NOT NULL,
                to_addr     TEXT NOT NULL,
                amount      INTEGER NOT NULL,
                metadata    TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                signature   TEXT NOT NULL,
                pubkey      TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions (from_addr);
            CREATE INDEX IF NOT EXISTS idx_tx_to   ON transactions (to_addr);
            CREATE INDEX IF NOT EXISTS idx_tx_time ON transactions (timestamp);
            ",
        )
        .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut ledger = Self {
            conn,
            balances: BalanceTracker::new(),
            supply: SupplyTracker::default_config(),
            tx_ids: HashSet::new(),
        };

        ledger.replay()?;
        Ok(ledger)
    }

    /// Replay all transactions from the database to rebuild balances.
    fn replay(&mut self) -> Result<(), LedgerError> {
        let txs = Self::load_all_txs(&self.conn)?;

        for tx in txs {
            self.apply_tx(&tx)?;
            self.tx_ids.insert(tx.tx_id);
        }

        Ok(())
    }

    fn load_all_txs(conn: &Connection) -> Result<Vec<Transaction>, LedgerError> {
        let mut stmt = conn
            .prepare(
                "SELECT tx_id, tx_type, from_addr, to_addr, amount, metadata, timestamp, signature, pubkey
                 FROM transactions ORDER BY rowid",
            )
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let rows = stmt.query_map([], |row| {
            let tx_type_str: String = row.get(1)?;
            let metadata_str: String = row.get(5)?;
            Ok(Transaction {
                tx_id: row.get(0)?,
                tx_type: serde_json::from_str(&format!("\"{}\"", tx_type_str))
                    .unwrap_or(TransactionType::Transfer),
                from: Address(row.get(2)?),
                to: Address(row.get(3)?),
                amount: row.get::<_, i64>(4)? as u64,
                metadata: serde_json::from_str(&metadata_str).unwrap_or(serde_json::json!({})),
                timestamp: row.get(6)?,
                signature: row.get(7)?,
                pubkey: row.get(8)?,
            })
        })
        .map_err(|e| LedgerError::Database(e.to_string()))?;

        let result = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Apply a transaction's effects to balances and supply.
    fn apply_tx(&mut self, tx: &Transaction) -> Result<(), LedgerError> {
        match tx.tx_type {
            TransactionType::Mint => {
                self.supply.mint(tx.amount)?;
                self.balances.credit(&tx.to, tx.amount);
            }
            TransactionType::Burn => {
                self.balances.debit(&tx.from, tx.amount)?;
                self.supply.burn(tx.amount);
            }
            TransactionType::Transfer
            | TransactionType::PushFee
            | TransactionType::PullFee
            | TransactionType::StorageReward
            | TransactionType::ChallengeReward
            | TransactionType::BandwidthReward => {
                if tx.from == Address::system() {
                    // Reward from system: just credit
                    self.supply.mint(tx.amount)?;
                    self.balances.credit(&tx.to, tx.amount);
                } else {
                    self.balances.transfer(&tx.from, &tx.to, tx.amount)?;
                }
            }
        }
        Ok(())
    }

    /// Append a new transaction to the ledger.
    ///
    /// Validates:
    /// - Signature is valid for the 'from' address
    /// - No duplicate tx_id
    /// - Sufficient balance for debits
    pub fn append(&mut self, tx: Transaction) -> Result<(), LedgerError> {
        // Signature Verification (skip for system address)
        if tx.from != Address::system() {
            // 1. Verify that the pubkey hashes to the 'from' address
            let pubkey_bytes = hex::decode(&tx.pubkey)
                .map_err(|_| LedgerError::InvalidTransaction("Invalid hex in pubkey".to_string()))?;
            let derived_addr = sha256_hex(&pubkey_bytes);
            if derived_addr != tx.from.0 {
                return Err(LedgerError::InvalidSignature);
            }

            // 2. Verify the Ed25519 signature
            let pk = PublicKey {
                bytes: pubkey_bytes,
            };
            let sig_bytes = hex::decode(&tx.signature)
                .map_err(|_| LedgerError::InvalidTransaction("Invalid hex in signature".to_string()))?;
            if !pk.verify(&tx.signable_bytes(), &sig_bytes) {
                return Err(LedgerError::InvalidSignature);
            }
        }

        // Duplicate check
        if self.tx_ids.contains(&tx.tx_id) {
            return Err(LedgerError::DuplicateTransaction(tx.tx_id.clone()));
        }

        // Apply to balances (validates balance sufficiency)
        self.apply_tx(&tx)?;

        // Persist to SQLite
        let tx_type_str = serde_json::to_string(&tx.tx_type)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        self.conn
            .execute(
                "INSERT INTO transactions (tx_id, tx_type, from_addr, to_addr, amount, metadata, timestamp, signature, pubkey)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    tx.tx_id,
                    tx_type_str,
                    tx.from.0,
                    tx.to.0,
                    tx.amount as i64,
                    serde_json::to_string(&tx.metadata).unwrap_or_default(),
                    tx.timestamp,
                    tx.signature,
                    tx.pubkey,
                ],
            )
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        self.tx_ids.insert(tx.tx_id);
        Ok(())
    }

    /// Get balance for an address.
    pub fn balance(&self, addr: &Address) -> MicroGitGold {
        self.balances.balance(addr)
    }

    /// Get all balances.
    pub fn balances(&self) -> &BalanceTracker {
        &self.balances
    }

    /// Get supply tracker.
    pub fn supply(&self) -> &SupplyTracker {
        &self.supply
    }

    /// Build a Merkle tree over all transaction hashes.
    pub fn merkle_tree(&self) -> Result<MerkleTree, LedgerError> {
        let txs = Self::load_all_txs(&self.conn)?;
        let hashes: Vec<[u8; 32]> = txs.iter().map(|tx| tx.hash()).collect();
        Ok(MerkleTree::build(hashes))
    }

    /// Total number of transactions.
    pub fn tx_count(&self) -> usize {
        self.tx_ids.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitgold_crypto::keys::KeyPair;

    fn mint_tx(to: &str, amount: MicroGitGold) -> Transaction {
        Transaction {
            tx_id: uuid::Uuid::new_v4().to_string(),
            tx_type: TransactionType::Mint,
            from: Address::system(),
            to: Address::new(to),
            amount,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
            pubkey: String::new(),
        }
    }

    fn transfer_tx(kp: &KeyPair, to: &str, amount: MicroGitGold) -> Transaction {
        let mut tx = Transaction {
            tx_id: uuid::Uuid::new_v4().to_string(),
            tx_type: TransactionType::Transfer,
            from: kp.address(),
            to: Address::new(to),
            amount,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
            pubkey: hex::encode(kp.public_key().bytes),
        };
        tx.signature = hex::encode(kp.sign(&tx.signable_bytes()));
        tx
    }

    #[test]
    fn test_mint_and_balance() {
        let mut ledger = Ledger::in_memory().unwrap();
        ledger.append(mint_tx("alice", 1_000_000)).unwrap();
        assert_eq!(ledger.balance(&Address::new("alice")), 1_000_000);
    }

    #[test]
    fn test_transfer_updates_balances() {
        let mut ledger = Ledger::in_memory().unwrap();
        let alice_kp = KeyPair::generate();
        let alice_addr = alice_kp.address();

        ledger.append(mint_tx(&alice_addr.0, 1_000_000)).unwrap();
        ledger
            .append(transfer_tx(&alice_kp, "bob", 400_000))
            .unwrap();

        assert_eq!(ledger.balance(&alice_addr), 600_000);
        assert_eq!(ledger.balance(&Address::new("bob")), 400_000);
    }

    #[test]
    fn test_double_spend_rejected() {
        let mut ledger = Ledger::in_memory().unwrap();
        let alice_kp = KeyPair::generate();
        let alice_addr = alice_kp.address();

        ledger.append(mint_tx(&alice_addr.0, 500_000)).unwrap();
        ledger
            .append(transfer_tx(&alice_kp, "bob", 300_000))
            .unwrap();

        // Alice only has 200k left, can't send 300k
        let result = ledger.append(transfer_tx(&alice_kp, "charlie", 300_000));
        assert!(matches!(
            result,
            Err(LedgerError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn test_signature_verification_failure() {
        let mut ledger = Ledger::in_memory().unwrap();
        let alice_kp = KeyPair::generate();
        let bob_kp = KeyPair::generate();
        let alice_addr = alice_kp.address();

        ledger.append(mint_tx(&alice_addr.0, 1_000_000)).unwrap();

        // Bob tries to spend Alice's money
        let mut bad_tx = transfer_tx(&bob_kp, "mallory", 300_000);
        bad_tx.from = alice_addr; // forge 'from' address

        let result = ledger.append(bad_tx);
        assert!(matches!(result, Err(LedgerError::InvalidSignature)));
    }

    #[test]
    fn test_duplicate_tx_rejected() {
        let mut ledger = Ledger::in_memory().unwrap();
        let tx = mint_tx("alice", 1_000_000);
        let tx_id = tx.tx_id.clone();
        ledger.append(tx).unwrap();

        let duplicate = Transaction {
            tx_id: tx_id,
            tx_type: TransactionType::Mint,
            from: Address::system(),
            to: Address::new("alice"),
            amount: 999,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
            pubkey: String::new(),
        };
        assert!(matches!(
            ledger.append(duplicate),
            Err(LedgerError::DuplicateTransaction(_))
        ));
    }

    #[test]
    fn test_burn() {
        let mut ledger = Ledger::in_memory().unwrap();
        let alice_kp = KeyPair::generate();
        let alice_addr = alice_kp.address();

        ledger.append(mint_tx(&alice_addr.0, 1_000_000)).unwrap();

        let mut burn = Transaction {
            tx_id: uuid::Uuid::new_v4().to_string(),
            tx_type: TransactionType::Burn,
            from: alice_addr.clone(),
            to: Address::system(),
            amount: 100_000,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
            pubkey: hex::encode(alice_kp.public_key().bytes),
        };
        burn.signature = hex::encode(alice_kp.sign(&burn.signable_bytes()));

        ledger.append(burn).unwrap();
        assert_eq!(ledger.balance(&alice_addr), 900_000);
        assert_eq!(ledger.supply().total_burned(), 100_000);
    }

    #[test]
    fn test_merkle_tree() {
        let mut ledger = Ledger::in_memory().unwrap();
        ledger.append(mint_tx("alice", 1_000_000)).unwrap();
        ledger.append(mint_tx("bob", 2_000_000)).unwrap();

        let tree = ledger.merkle_tree().unwrap();
        assert_eq!(tree.leaf_count(), 2);

        // Root should be non-zero
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_tx_count() {
        let mut ledger = Ledger::in_memory().unwrap();
        assert_eq!(ledger.tx_count(), 0);
        ledger.append(mint_tx("alice", 100)).unwrap();
        assert_eq!(ledger.tx_count(), 1);
        ledger.append(mint_tx("bob", 200)).unwrap();
        assert_eq!(ledger.tx_count(), 2);
    }
}
