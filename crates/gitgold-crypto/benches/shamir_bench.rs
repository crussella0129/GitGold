use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use gitgold_crypto::shamir::{reconstruct, split};

fn shamir_split(c: &mut Criterion) {
    let configs: &[(usize, usize)] = &[(3, 5), (5, 9)];
    let sizes: &[(usize, &str)] = &[
        (32, "32B"),
        (1024, "1KB"),
        (32 * 1024, "32KB"),
        (512 * 1024, "512KB"),
    ];

    let mut group = c.benchmark_group("shamir_split");
    for &(size, label) in sizes {
        let secret = vec![0xABu8; size];
        for &(k, n) in configs {
            group.bench_with_input(
                BenchmarkId::new(format!("k{k}_n{n}"), label),
                &(&secret, k, n),
                |bench, &(secret, k, n)| {
                    bench.iter(|| split(black_box(secret), black_box(k), black_box(n)).unwrap())
                },
            );
        }
    }
    // Larger sizes need fewer samples
    group.sample_size(10);
    group.finish();
}

fn shamir_reconstruct(c: &mut Criterion) {
    let configs: &[(usize, usize)] = &[(3, 5), (5, 9)];
    let sizes: &[(usize, &str)] = &[
        (32, "32B"),
        (1024, "1KB"),
        (32 * 1024, "32KB"),
        (512 * 1024, "512KB"),
    ];

    let mut group = c.benchmark_group("shamir_reconstruct");
    group.sample_size(10);
    for &(size, label) in sizes {
        let secret = vec![0xABu8; size];
        for &(k, n) in configs {
            let shares = split(&secret, k, n).unwrap();
            group.bench_with_input(
                BenchmarkId::new(format!("k{k}_n{n}"), label),
                &(&shares, k),
                |bench, &(shares, k)| {
                    bench.iter(|| reconstruct(black_box(shares), black_box(k)).unwrap())
                },
            );
        }
    }
    group.finish();
}

fn shamir_roundtrip(c: &mut Criterion) {
    let secret = vec![0x42u8; 32]; // single block
    c.bench_function("shamir_roundtrip_32B_k3n5", |bench| {
        bench.iter(|| {
            let shares = split(black_box(&secret), 3, 5).unwrap();
            reconstruct(black_box(&shares), 3).unwrap()
        })
    });
}

criterion_group!(benches, shamir_split, shamir_reconstruct, shamir_roundtrip,);
criterion_main!(benches);
