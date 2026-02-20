use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gitgold_crypto::field::FieldElement;
use num_bigint::BigUint;

fn field_add(c: &mut Criterion) {
    let a = FieldElement::from_u64(123_456_789);
    let b = FieldElement::from_u64(987_654_321);
    c.bench_function("field_add", |bench| {
        bench.iter(|| black_box(a.clone()) + black_box(b.clone()))
    });
}

fn field_mul(c: &mut Criterion) {
    let a = FieldElement::from_u64(123_456_789);
    let b = FieldElement::from_u64(987_654_321);
    c.bench_function("field_mul", |bench| {
        bench.iter(|| black_box(a.clone()) * black_box(b.clone()))
    });
}

fn field_inv(c: &mut Criterion) {
    let a = FieldElement::from_u64(123_456_789);
    c.bench_function("field_inv", |bench| {
        bench.iter(|| black_box(a.clone()).inv())
    });
}

fn field_div(c: &mut Criterion) {
    let a = FieldElement::from_u64(123_456_789);
    let b = FieldElement::from_u64(987_654_321);
    c.bench_function("field_div", |bench| {
        bench.iter(|| black_box(a.clone()) / black_box(b.clone()))
    });
}

fn field_mul_256bit(c: &mut Criterion) {
    // Full 256-bit operands (just under the prime)
    let bytes_a = [0xAB; 32];
    let bytes_b = [0xCD; 32];
    let a = FieldElement::from_bytes_be(&bytes_a);
    let b = FieldElement::from_bytes_be(&bytes_b);
    c.bench_function("field_mul_256bit", |bench| {
        bench.iter(|| black_box(a.clone()) * black_box(b.clone()))
    });
}

fn field_inv_256bit(c: &mut Criterion) {
    let bytes = [0xAB; 32];
    let a = FieldElement::from_bytes_be(&bytes);
    c.bench_function("field_inv_256bit", |bench| {
        bench.iter(|| black_box(a.clone()).inv())
    });
}

fn field_from_bytes_be(c: &mut Criterion) {
    let bytes = [0x42u8; 32];
    c.bench_function("field_from_bytes_be", |bench| {
        bench.iter(|| FieldElement::from_bytes_be(black_box(&bytes)))
    });
}

fn field_to_bytes_be(c: &mut Criterion) {
    let a = FieldElement::new(BigUint::from_bytes_be(&[0xAB; 32]));
    c.bench_function("field_to_bytes_be", |bench| {
        bench.iter(|| black_box(&a).to_bytes_be())
    });
}

criterion_group!(
    benches,
    field_add,
    field_mul,
    field_inv,
    field_div,
    field_mul_256bit,
    field_inv_256bit,
    field_from_bytes_be,
    field_to_bytes_be,
);
criterion_main!(benches);
