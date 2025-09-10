use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;

const SECURITY_LEVELS: [(u32, u32); 6] = [
    (1, 64), // for toy example only
    (80, 1024),
    (112, 2048),
    (128, 3072),
    (192, 7680),
    (256, 15360),
];

fn generate_large_prime(bit_length: u32) -> BigInt {
    let mut rng = rand::rng();
    loop {
        // Generate random bytes and convert to BigInt
        let mut bytes = vec![0u8; (bit_length as usize + 7) / 8];
        rng.fill_bytes(&mut bytes);
        let candidate = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes) | BigInt::one();
        if is_prime(&candidate) {
            return candidate;
        }
    }
}

/// Miller-Rabin primality test
fn is_prime(n: &BigInt) -> bool {
    if n <= &BigInt::one() {
        return false;
    }
    if n == &BigInt::from(2u32) || n == &BigInt::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    let mut d = n - BigInt::one();
    let mut s = 0;
    while d.is_even() {
        d = d >> 1;
        s += 1;
    }

    let bases = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
    ].iter().map(|&x| BigInt::from(x)).collect::<Vec<_>>();

    'next_base: for base in bases {
        if base >= *n {
            continue;
        }
        let mut x = base.modpow(&d, n);
        if x == BigInt::one() || x == n - BigInt::one() {
            continue;
        }
        for _ in 0..s - 1 {
            x = x.modpow(&BigInt::from(2u32), n);
            if x == n - BigInt::one() {
                continue 'next_base;
            }
        }
        return false;
    }
    true
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = extended_gcd(&(b % a), a);
        (g, y - (b / a) * x.clone(), x)
    }
}

fn mod_inverse(a: BigInt, m: BigInt) -> Option<BigInt> {
    let (g, x, _) = extended_gcd(&a, &m);
    if g != BigInt::one() {
        None
    } else {
        Some((x % &m + &m) % m)
    }
}

pub fn generate(security_level: u32) -> (BigInt, BigInt, BigInt, BigInt, BigInt) {
    let modulus_bits = SECURITY_LEVELS.iter()
        .find(|&&(sl, _)| sl == security_level)
        .map(|&(_, mb)| mb)
        .expect("Invalid security level");

    let p = generate_large_prime(modulus_bits / 2);
    let q = generate_large_prime(modulus_bits / 2);
    let n = &p * &q;
    let phi = (&p - BigInt::one()) * (&q - BigInt::one());

    let e = BigInt::from(65537u32);
    let d = mod_inverse(e.clone(), phi).expect("No modular inverse exists");

    (p, q, n, e, d)
}

pub fn encrypt(m: &BigInt, e: &BigInt, n: &BigInt) -> BigInt {
    m.modpow(e, n)
}

pub fn decrypt(c: &BigInt, d: &BigInt, n: &BigInt) -> BigInt {
    c.modpow(d, n)
}

fn main() {
    let security_level = 1; // 128
    let (p, q, n, e, d) = generate(security_level);

    println!("Generated RSA parameters:");
    println!("p = {}", p);
    println!("q = {}", q);
    println!("n = {}", n);
    println!("e = {}", e);
    println!("d = {}", d);

    let message = BigInt::from(11451419198100721u64);
    println!("\nOriginal message: {}", message);

    let ciphertext = encrypt(&message, &e, &n);
    println!("Encrypted: {}", ciphertext);

    let decrypted = decrypt(&ciphertext, &d, &n);
    println!("Decrypted: {}", decrypted);

    assert_eq!(message, decrypted, "Decryption failed!");
    println!("Decryption successful!");
}