use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gitgold_challenge::challenge::Challenge;
use gitgold_challenge::proof::ChallengeProof;
use gitgold_challenge::validator::validate_challenge_response;
use gitgold_core::config::GitGoldConfig;
use gitgold_crypto::keys::KeyPair;

const FRAGMENT_SIZE: usize = 100_000; // 100KB, matches integration tests

fn challenge_generate(c: &mut Criterion) {
    let config = GitGoldConfig::default();
    c.bench_function("challenge_generate", |bench| {
        bench.iter(|| {
            Challenge::generate(
                black_box("repo_hash_abc123"),
                black_box(0),
                black_box(1),
                black_box(FRAGMENT_SIZE),
                black_box(&config),
            )
            .unwrap()
        })
    });
}

fn proof_create(c: &mut Criterion) {
    let config = GitGoldConfig::default();
    let fragment_data = vec![0xABu8; FRAGMENT_SIZE];
    let challenge = Challenge::generate("repo_hash", 0, 1, FRAGMENT_SIZE, &config).unwrap();
    let kp = KeyPair::generate();

    c.bench_function("proof_create", |bench| {
        bench.iter(|| {
            ChallengeProof::create(
                black_box(&challenge),
                black_box(&fragment_data),
                black_box(100),
                |msg| hex::encode(kp.sign(msg)),
            )
        })
    });
}

fn validate_response(c: &mut Criterion) {
    let config = GitGoldConfig::default();
    let fragment_data = vec![0xABu8; FRAGMENT_SIZE];
    let challenge = Challenge::generate("repo_hash", 0, 1, FRAGMENT_SIZE, &config).unwrap();
    let kp = KeyPair::generate();
    let proof = ChallengeProof::create(&challenge, &fragment_data, 100, |msg| {
        hex::encode(kp.sign(msg))
    });
    let pk = kp.public_key();

    c.bench_function("validate_challenge_response", |bench| {
        bench.iter(|| {
            validate_challenge_response(
                black_box(&challenge),
                black_box(&proof),
                black_box(&fragment_data),
                black_box(&pk),
                black_box(&config),
            )
            .unwrap()
        })
    });
}

fn full_challenge_cycle(c: &mut Criterion) {
    let config = GitGoldConfig::default();
    let fragment_data = vec![0xABu8; FRAGMENT_SIZE];
    let kp = KeyPair::generate();
    let pk = kp.public_key();

    c.bench_function("full_challenge_cycle", |bench| {
        bench.iter(|| {
            let challenge =
                Challenge::generate("repo_hash", 0, 1, FRAGMENT_SIZE, &config).unwrap();
            let proof = ChallengeProof::create(&challenge, &fragment_data, 100, |msg| {
                hex::encode(kp.sign(msg))
            });
            validate_challenge_response(&challenge, &proof, &fragment_data, &pk, &config).unwrap()
        })
    });
}

criterion_group!(
    benches,
    challenge_generate,
    proof_create,
    validate_response,
    full_challenge_cycle,
);
criterion_main!(benches);
