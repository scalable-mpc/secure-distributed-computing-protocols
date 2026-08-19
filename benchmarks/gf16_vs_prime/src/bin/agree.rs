fn main() {
    for &(k, n) in &[(2usize,4usize),(3,8),(6,16),(16,32),(32,64),(64,128),(86,256),(128,256)] {
        for &l in &[64usize, 1024] {
            match gf16_vs_prime::rs::check_agreement(k, n, l) {
                Ok(()) => println!("k={k:<4} n={n:<4} l={l:<5} matrix == ntt  OK"),
                Err(e) => { println!("FAIL {e}"); std::process::exit(1); }
            }
        }
    }
    for &(k,m) in &[(2usize,2usize),(6,10),(22,42),(44,84),(86,170)] {
        match gf16_vs_prime::rs::check_systematic(k,m,1024) {
            Ok(())=>println!("k={k:<4} m={m:<4} systematic cauchy: avx2 == scalar  OK"),
            Err(e)=>{println!("FAIL {e}"); std::process::exit(1);}
        }
    }
    for &(k,m) in &[(2usize,2usize),(6,10),(22,42),(44,84),(86,170)] {
        match gf16_vs_prime::rs::check_systematic_ntt(k,m,256) {
            Ok(())=>println!("k={k:<4} m={m:<4} systematic ntt vs Horner:   OK"),
            Err(e)=>{println!("FAIL {e}"); std::process::exit(1);}
        }
    }
    for &(k,n) in &[(2usize,4usize),(6,16),(12,32),(22,64),(44,128),(86,256)] {
        match gf16_vs_prime::rs::check_decode(k,n,512,0xABCDEF) {
            Ok(d)=>println!("k={k:<4} n={n:<4} decode from {k} random shards ({d} of them data): OK"),
            Err(e)=>{println!("FAIL {e}"); std::process::exit(1);}
        }
    }
    println!("\ngenerator of F_12289* = {}", gf16_vs_prime::rs::generator());
}
