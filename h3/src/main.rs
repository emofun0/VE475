// AES multiplication helper
fn time_x(b: u8) -> u8 {
    let mut result = b << 1;
    if b & 0x80 != 0 {
        result ^= 0x1b;
    }
    result
}

fn time_x_1(b: u8) -> u8 {
    time_x(b) ^ b
}


fn shift_rows(state: &mut [[u8; 4]; 4]) {
    // line1
    // line2
    state[1].rotate_left(1);
    // line3
    state[2].rotate_left(2);
    // line4
    state[3].rotate_left(3);
}

fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for col in 0..4 {
        let a0 = state[0][col];
        let a1 = state[1][col];
        let a2 = state[2][col];
        let a3 = state[3][col];
        
        state[0][col] = time_x(a0) ^ time_x_1(a1) ^ a2 ^ a3; // 10 11 01 01
        state[1][col] = a0 ^ time_x(a1) ^ time_x_1(a2) ^ a3; // 01 10 11 01
        state[2][col] = a0 ^ a1 ^ time_x(a2) ^ time_x_1(a3); // 01 01 10 11
        state[3][col] = time_x_1(a0) ^ a1 ^ a2 ^ time_x(a3); // 11 01 01 10
    }
}

fn print_state(title: &str, state: &[[u8; 4]; 4]) {
    println!("{}:", title);
    for row in state {
        print!("[");
        for (i, &byte) in row.iter().enumerate() {
            print!("{:02x}{}", byte, if i < 3 { " " } else { "" });
        }
        println!("]");
    }
    println!();
}

fn main() {
    let mut state: [[u8; 4]; 4] = [
        [0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34],
    ];
    
    print_state("Initial state:", &state);
    
    shift_rows(&mut state);
    print_state("After ShiftRows:", &state);
    
    mix_columns(&mut state);
    print_state("After MixColumns: ", &state);
}
