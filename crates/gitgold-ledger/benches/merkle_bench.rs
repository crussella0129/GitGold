use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use gitgold_crypto::hash::sha256;
use gitgold_ledger::merkle::MerkleTree;

fn merkle_build(c: &mut Criterion) {
    let leaf_counts = [10, 100, 1_000, 10_000, 100_000];

    let mut group = c.benchmark_group("merkle_build");
    for &count in &leaf_counts {
        // Pre-hash leaves so we benchmark tree construction, not hashing
        let leaves: Vec<[u8; 32]> = (0..count)
            .map(|i| sha256(&(i as u64).to_le_bytes()))
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &leaves,
            |bench, leaves| {
                bench.iter(|| MerkleTree::build(black_box(leaves.clone())))
            },
        );
    }
    group.finish();
}

fn merkle_proof(c: &mut Criterion) {
    let leaf_counts = [100, 1_000, 10_000];

    let mut group = c.benchmark_group("merkle_proof");
    for &count in &leaf_counts {
        let leaves: Vec<[u8; 32]> = (0..count)
            .map(|i| sha256(&(i as u64).to_le_bytes()))
            .collect();
        let tree = MerkleTree::build(leaves);

        // Prove middle leaf
        let index = count / 2;
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &(tree, index),
            |bench, (tree, index)| {
                bench.iter(|| tree.proof(black_box(*index)).unwrap())
            },
        );
    }
    group.finish();
}

fn merkle_verify(c: &mut Criterion) {
    let leaf_counts = [100, 1_000, 10_000];

    let mut group = c.benchmark_group("merkle_verify");
    for &count in &leaf_counts {
        let leaves: Vec<[u8; 32]> = (0..count)
            .map(|i| sha256(&(i as u64).to_le_bytes()))
            .collect();
        let tree = MerkleTree::build(leaves.clone());
        let root = tree.root();

        let index = count / 2;
        let leaf_hash = leaves[index];
        let proof = tree.proof(index).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &(leaf_hash, &proof, root),
            |bench, &(leaf_hash, proof, root)| {
                bench.iter(|| {
                    MerkleTree::verify_proof(black_box(leaf_hash), black_box(proof), black_box(root))
                })
            },
        );
    }
    group.finish();
}

fn merkle_from_data(c: &mut Criterion) {
    // 1000 raw data leaves — measures hash + build combined
    let raw_data: Vec<Vec<u8>> = (0..1_000)
        .map(|i| format!("leaf-data-{i}").into_bytes())
        .collect();
    let refs: Vec<&[u8]> = raw_data.iter().map(|v| v.as_slice()).collect();

    c.bench_function("merkle_from_data_1000", |bench| {
        bench.iter(|| MerkleTree::from_data(black_box(&refs)))
    });
}

criterion_group!(benches, merkle_build, merkle_proof, merkle_verify, merkle_from_data,);
criterion_main!(benches);
