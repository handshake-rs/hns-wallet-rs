use std::{
    env,
    fs::File,
    io::{BufReader, Read},
};

use hns_header_consensus::{HEADER_SIZE, Header, Network};
use hns_light_chain::{ChainLimits, LightChain};
use hns_primitives::BlockTime;

const ENVELOPE_BYTES: u64 = 51;

fn main() {
    let path = env::args().nth(1).expect("snapshot path");
    let target: u32 = env::args()
        .nth(2)
        .expect("target height")
        .parse()
        .expect("height");
    let file = File::open(path).expect("open snapshot");
    let mut reader = BufReader::new(file);
    let mut envelope = [0_u8; ENVELOPE_BYTES as usize];
    reader.read_exact(&mut envelope).expect("read envelope");
    let mut chain = LightChain::from_genesis(
        Network::Mainnet,
        BlockTime::new(u64::MAX / 2),
        ChainLimits::default(),
    )
    .expect("genesis");
    let mut encoded = [0_u8; HEADER_SIZE];
    reader.read_exact(&mut encoded).expect("read genesis");
    let genesis = Header::decode(&encoded).expect("decode genesis");
    assert_eq!(
        genesis.block_hash(),
        Network::Mainnet.parameters().genesis_hash
    );
    for height in 1..=target {
        let mut encoded = [0_u8; HEADER_SIZE];
        reader.read_exact(&mut encoded).expect("read header");
        let header = Header::decode(&encoded).expect("decode header");
        chain
            .append(&header, BlockTime::new(u64::MAX / 2))
            .expect("validate header");
        if height % 50_000 == 0 {
            eprintln!("validated {height}");
        }
    }
    let tip = chain.tip();
    let snapshot = chain
        .encode_authenticated_snapshot()
        .expect("encode checkpoint");
    println!("height={}", tip.height().get());
    println!("hash={}", hex::encode(tip.hash().as_bytes()));
    println!("chainwork={}", hex::encode(tip.chainwork().to_be_bytes()));
    println!("snapshot_bytes={}", snapshot.len());
    println!("snapshot_hex={}", hex::encode(snapshot));
}
