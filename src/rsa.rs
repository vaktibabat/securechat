use num_bigint::{BigUint, RandBigInt};
use rand::{self, thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const RSA_EXP: u64 = 65537u64;
/// N size in bytes
pub const N_SIZE: usize = 256;

/// RSA Public Key
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Exponent
    pub e: BigUint,
    /// n = p*q
    pub n: BigUint,
}

/// RSA Private Key
#[derive(Clone)]
pub struct PrivateKey {
    /// First prime factor: p
    p: BigUint,
    /// Second prime factor: q
    q: BigUint,
    /// d - multiplicative inverse of e mod n
    d: BigUint,
}

/// A keypair for a peer
#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl Keypair {
    // p and q can be provided if we have a predefined p and q,
    // like in the case of the TTP
    pub fn new(p: Option<BigUint>, q: Option<BigUint>) -> Keypair {
        let p = if let Some(p) = p { p } else { gen_prime(1024) };
        let q = if let Some(q) = q { q } else { gen_prime(1024) };
        let e = BigUint::from(RSA_EXP);
        let n = &p * &q;
        let phi_n = (&p - 1u64) * (&q - 1u64);
        let d = e.modinv(&phi_n).unwrap();
        let public = PublicKey { e, n };
        let private = PrivateKey { p, q, d };

        Keypair { public, private }
    }

    /// Validate a signature on a message
    pub fn validate(&self, m: &BigUint, s: &BigUint) -> bool {
        s.modpow(&self.public.e, &self.public.n) == *m
    }

    /// Sign a message using the private key
    pub fn sign(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.private.d, &self.public.n)
    }
}

impl PublicKey {
    /// Encrypt a message under this public key
    /// the message is padded with OAEP padding (todo)
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }
}

impl PrivateKey {
    /// Decrypt a message under this private key
    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        c.modpow(&self.d, &(&self.p * &self.q))
    }
}

/// Factor n into the form n = 2^{s} * d, where d is odd
/// Used in Rabin-Miller
fn factor(n: &BigUint) -> (BigUint, BigUint) {
    let mut s: BigUint = BigUint::from(0u64);
    let mut d = n.clone();

    while &d % BigUint::from(2u64) == BigUint::from(0u64) {
        s += BigUint::from(1u64);
        d /= BigUint::from(2u64);
    }

    (s, d)
}

/// The Miller-Rabin primality test
/// We know that n is prime if and only if the solutions of x^2 = 1 (mod n) are x = plus minus 1
/// So we can check whether a^2 = 1 (mod n) for random a, k times.
fn miller_rabin_test(n: &BigUint, k: usize) -> bool {
    if n % (2_usize) == BigUint::from(0u64) {
        return false;
    }

    let (s, d) = factor(&(n - BigUint::from(1_usize)));

    for _ in 0..k {
        let a = thread_rng().gen_biguint_range(&BigUint::from(2u64), &(n - 2u64));
        let mut x = a.modpow(&d, n);

        for _ in num_iter::range(BigUint::from(0u64), s.clone()) {
            let y = x.modpow(&BigUint::from(2u64), n);

            // We found a nontrivial root
            if y == BigUint::from(1u64) && x != BigUint::from(1u64) && x != n - 1u64 {
                return false;
            }

            x = y;
        }

        // Fermat test: at this point x = a^{n - 1} mod n
        if x != BigUint::from(1u64) {
            return false;
        }
    }

    true
}

/// Generate a random prime with specified number of bits
pub fn gen_prime(bits: u64) -> BigUint {
    let mut rng = ChaCha20Rng::from_entropy();
    
    // Primes are pretty common: The prime-counting function (number of primes smaller than some real number x)
    // is approximately x / log x, which means that we have p_n ~ n * log(n), where p_n is the n-th -prime
    // Therefore, the method we use to generate prime numbers is to generate random numbers with the specified number of bits
    // until we hit a prime number.
    loop {
        let mut bytes = [0u8; N_SIZE / 2];
        rng.fill_bytes(&mut bytes);
        let candidate = BigUint::from_bytes_be(&bytes);

        if miller_rabin_test(&candidate, 12) {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miller_rabin_test_test() {
        let my_prime_bytes = b"CE4CB4C8CB1FC2685FA2D4245FF1E8A2E0627A65C5E7E43D2C6339D4C9145FAB933EFEC21F5B32F55EC4DF5452D4BCBACED415254C263A64B84DC543C35559A10BD5C3EF922812A3C6504768456C3F5822B244BB7BA8C621972383DA45E54B5A66EFAFADB8FAA5F30E82FD7F29159D9B71F46E1EF7DC77609A4D63ABF917D5C0FB8D7350C8027594E462C6AD5BFC99D51EAE52FF41AD04D0AC2EB71B74D6242C947C5BE80C1EB7F37EC2E1256E83B67A4E31340E5ABED3B2FD6FB25DB4694088BD78DB947C7AC9796DA42314012FBB9F1DA5DD9E33684881E194F20B232BE93498280FBD4E78F7D237D8C1FE957DB8F53239E901C80A414B6138E51F73EC3A71";
        let my_prime = BigUint::parse_bytes(my_prime_bytes, 16).unwrap();
        let composite_bytes = b"DE4CB4C8CB1FC2685FA2D4245FF1E8A2E0627A65C5E7E43D2C6339D4C9145FAB933EFEC21F5B32F55EC4DF5452D4BCBACED415254C263A64B84DC543C35559A10BD5C3EF922812A3C6504768456C3F5822B244BB7BA8C621972383DA45E54B5A66EFAFADB8FAA5F30E82FD7F29159D9B71F46E1EF7DC77609A4D63ABF917D5C0FB8D7350C8027594E462C6AD5BFC99D51EAE52FF41AD04D0AC2EB71B74D6242C947C5BE80C1EB7F37EC2E1256E83B67A4E31340E5ABED3B2FD6FB25DB4694088BD78DB947C7AC9796DA42314012FBB9F1DA5DD9E33684881E194F20B232BE93498280FBD4E78F7D237D8C1FE957DB8F53239E901C80A414B6138E51F73EC3A71";
        let my_composite = BigUint::parse_bytes(composite_bytes, 16).unwrap();
        // Carmichael number
        let carmichael = BigUint::from(41041u64);

        assert_eq!(miller_rabin_test(&my_prime, 13), true);
        assert_eq!(miller_rabin_test(&carmichael, 13), false);
        assert_eq!(miller_rabin_test(&my_composite, 13), false);
    }

    #[test]
    fn factor_test() {
        // 12524 = 2^2 * 3131
        let number = BigUint::from(12524 as usize);

        assert_eq!(
            factor(&number),
            (BigUint::from(2 as usize), BigUint::from(3131 as usize))
        );
    }

    #[test]
    fn gen_prime_test() {
        let p = gen_prime(1024);

        println!("The prime is {}", p);

        assert_eq!(miller_rabin_test(&p, 40), true);
    }

    #[test]
    fn encrypt_decrypt_test() {
        let message = BigUint::from_bytes_be(b"ATTACK AT DAWN");
        let keypair = Keypair::new(None, None);
        let ciphertext = keypair.public.encrypt(&message);
        let decrypted_ciphertext = keypair.private.decrypt(&ciphertext);
        let decrypted_ciphertext_string =
            String::from_utf8(decrypted_ciphertext.to_bytes_be()).unwrap();

        assert_eq!(decrypted_ciphertext_string, "ATTACK AT DAWN");
    }
}
