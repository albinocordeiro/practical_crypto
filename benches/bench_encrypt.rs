use criterion::{criterion_group, criterion_main, Criterion};
use practical_crypto::aes::*;

fn encrypt_benchmark_func(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_decrypt");
    group.bench_function("encrypt_decrypt", |b| {
        b.iter(|| {
            encrypt_file("./benches/bookchapter.txt", "./benches/bookchapter.enc", "./benches/cipher.key").unwrap();
        })
    });
}
criterion_group!(benches, encrypt_benchmark_func);
criterion_main!(benches);