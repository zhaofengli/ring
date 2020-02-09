/// RSA key pair components.
pub struct Components<B: AsRef<[u8]>> {
    /// The public key components.
    pub public_key: super::super::public::Components<B>,

    /// The private exponent.
    pub d: B,

    /// The first prime factor of `d`.
    pub p: B,

    /// The second prime factor of `d`.
    pub q: B,

    /// `p`'s public Chinese Remainder Theorem exponent.
    pub dP: B,

    /// `q`'s public Chinese Remainder Theorem exponent.
    pub dQ: B,

    /// `q**-1 mod p`.
    pub qInv: B,
}

impl<B: Copy> Copy for Components<B> where B: AsRef<[u8]> {}

impl<B: Clone> Clone for Components<B>
where
    B: AsRef<[u8]>,
{
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            d: self.d.clone(),
            p: self.p.clone(),
            q: self.q.clone(),
            dP: self.dP.clone(),
            dQ: self.dQ.clone(),
            qInv: self.qInv.clone(),
        }
    }
}

impl<B> core::fmt::Debug for Components<B>
where
    B: AsRef<[u8]> + core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        // Non-public components are intentionally skipped
        f.debug_struct("Components")
            .field("public_key", &self.public_key)
            .finish()
    }
}
