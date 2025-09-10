use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::One;
use num_traits::Signed;

pub fn pollards_rho(n: &BigInt) -> Option<BigInt> {
    let one = BigInt::one();
    let two = BigInt::from(2u32);
    
    // f(x) = x^2 + 1 mod n
    let f = |x: &BigInt| (x.pow(2) + &one) % n;

    let mut a = two.clone();
    let mut b = two.clone();
    let mut d: BigInt;

    loop {
        // a = f(a)
        a = f(&a);
        // b = f(f(b))
        b = f(&f(&b));
        // d = gcd(a - b, n)
        d = (a.clone() - b.clone()).abs().gcd(n);
        
        if d != one {
            break;
        }
    }

    if d == *n {
        None
    } else {
        Some(d)
    }
}

fn main() {
    let n = BigInt::from(8051u32);
    let res = pollards_rho(&n);
    if res.is_none() {
        print!("{n} is prime.\n");
    } else {
        let factor = res.unwrap();
        print!("{n} is not prime. Found factor {factor}.\n");
    }
}