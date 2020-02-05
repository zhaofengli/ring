/// RSA public key components
pub struct Components<B: AsRef<[u8]>> {
    /// The public modulus, encoded in big-endian bytes without leading zeros.
    pub n: B,

    /// The public exponent, encoded in big-endian bytes without leading zeros.
    pub e: B,
}

impl<B: Copy> Copy for Components<B> where B: AsRef<[u8]> {}

impl<B: Clone> Clone for Components<B>
where
    B: AsRef<[u8]>,
{
    fn clone(&self) -> Self {
        Self {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }
}

impl<B> core::fmt::Debug for Components<B>
where
    B: AsRef<[u8]> + core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Components")
            .field("n", &self.n)
            .field("e", &self.e)
            .finish()
    }
}
