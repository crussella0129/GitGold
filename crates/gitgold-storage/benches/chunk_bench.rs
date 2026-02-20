use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use gitgold_storage::chunk::{chunk_data, reassemble_chunks, DEFAULT_CHUNK_SIZE};

fn bench_chunk_data(c: &mut Criterion) {
    let sizes: &[(usize, &str)] = &[
        (1_024, "1KB"),
        (64 * 1024, "64KB"),
        (512 * 1024, "512KB"),
        (1_500_000, "1.5MB"),
        (10_000_000, "10MB"),
    ];

    let mut group = c.benchmark_group("chunk_data");
    for &(size, label) in sizes {
        let data = vec![0xABu8; size];
        group.bench_with_input(BenchmarkId::new("default_chunk", label), &data, |bench, data| {
            bench.iter(|| chunk_data(black_box(data), DEFAULT_CHUNK_SIZE))
        });
    }
    group.finish();
}

fn bench_reassemble(c: &mut Criterion) {
    let sizes: &[(usize, &str)] = &[
        (1_024, "1KB"),
        (64 * 1024, "64KB"),
        (512 * 1024, "512KB"),
        (1_500_000, "1.5MB"),
        (10_000_000, "10MB"),
    ];

    let mut group = c.benchmark_group("reassemble_chunks");
    for &(size, label) in sizes {
        let data = vec![0xABu8; size];
        let chunks = chunk_data(&data, DEFAULT_CHUNK_SIZE);
        group.bench_with_input(
            BenchmarkId::new("default_chunk", label),
            &chunks,
            |bench, chunks| bench.iter(|| reassemble_chunks(black_box(chunks.clone()))),
        );
    }
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let data = vec![0x42u8; 1_500_000]; // 1.5MB
    c.bench_function("chunk_roundtrip_1.5MB", |bench| {
        bench.iter(|| {
            let chunks = chunk_data(black_box(&data), DEFAULT_CHUNK_SIZE);
            reassemble_chunks(black_box(chunks)).unwrap()
        })
    });
}

criterion_group!(benches, bench_chunk_data, bench_reassemble, bench_roundtrip,);
criterion_main!(benches);
