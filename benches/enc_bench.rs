use criterion::{black_box, Criterion};
use enc::{
    decrypt_with_key, encrypt_and_generate_key, encrypt_with_key, generate_aes256_key,
    string_generation,
};

const SIZE: usize = 10000;

fn crit_generate_key(c: &mut Criterion) {
    c.bench_function("generate_key", |b| {
        b.iter(|| {
            let _data = black_box(generate_aes256_key().unwrap());
        })
    });
}

fn crit_generate_string(c: &mut Criterion) {
    c.bench_function("generate_string", |b| {
        b.iter(|| {
            let _data = black_box(string_generation(SIZE));
        })
    });
}

criterion::criterion_group!(generation, crit_generate_key, crit_generate_string);

fn crit_only_encrypt(c: &mut Criterion) {
    let key = generate_aes256_key().unwrap();
    let data = string_generation(SIZE);
    c.bench_function("only encrypt", |b| {
        b.iter(|| {
            let _data = black_box(encrypt_with_key(data.clone(), key).unwrap());
        })
    });
}

fn crit_only_decrypt(c: &mut Criterion) {
    let key = generate_aes256_key().unwrap();
    let data = string_generation(SIZE);
    let encrypted_data = encrypt_with_key(data, key).unwrap();

    c.bench_function("only decrypt", |b| {
        b.iter(|| {
            let _data = black_box(decrypt_with_key(encrypted_data.clone(), key).unwrap());
        })
    });
}

fn crit_encrypt_with_keygen(c: &mut Criterion) {
    let data = string_generation(SIZE);

    c.bench_function("encrypt and key create", |b| {
        b.iter(|| {
            let _data = black_box(encrypt_and_generate_key(data.clone()).unwrap());
        })
    });
}

fn crit_encrypt_decrypt(c: &mut Criterion) {
    let data = string_generation(SIZE);
    c.bench_function("enc-dec", |b| {
        b.iter(|| {
            let (enc_data, key) = black_box(encrypt_and_generate_key(data.clone()).unwrap());
            let new_data = black_box(decrypt_with_key(enc_data, key).unwrap());
            new_data == data
        })
    });
}

criterion::criterion_group!(
    cryption,
    crit_only_encrypt,
    crit_only_decrypt,
    crit_encrypt_with_keygen,
    crit_encrypt_decrypt
);

criterion::criterion_main!(generation, cryption);
