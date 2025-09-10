use rug::Integer;

fn extended_gcd(a: &Integer, b: &Integer) -> (Integer, Integer, Integer)
{
    let mut r_prev = a.clone();
    let mut r = b.clone();
    let mut s_prev = Integer::from(1);
    let mut s = Integer::from(0);
    let mut t_prev = Integer::from(0);
    let mut t = Integer::from(1);

    while r != 0 
    {
        let q = Integer::from(&r_prev / &r);
        
        let r_temp = r_prev;
        r_prev = r.clone();
        r = r_temp - &q * r;

        let s_temp = s_prev;
        s_prev = r.clone();
        s = s_temp - &q * s;

        let t_temp = t_prev;
        t_prev = t.clone();
        t = t_temp - &q * t;
    }

    (r_prev, s_prev, t_prev)
}

fn main()
{
    use rug::Complete;
    let mut rng = rug::rand::RandState::new();
    let num1 = Integer::random_bits(4096, &mut rng).complete();
    let num2 = Integer::random_bits(4096, &mut rng).complete();

    let (gcd1, _, _) = extended_gcd(&num1, &num2);
    let gcd2 = num1.clone().gcd(&num2);

    println!("num1: {}", num1);
    println!("num2: {}", num2);
    println!("gcd1: {}", gcd1);
    println!("gcd2: {}", gcd2);
}
