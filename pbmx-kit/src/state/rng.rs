use crate::{
    crypto::{
        keys::Fingerprint,
        vtmf::{Mask, SecretShare, Vtmf},
    },
    Error,
};
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use digest::XofReader;
use std::fmt::{self, Debug, Display, Formatter};

/// An distributed random number generator
#[derive(Debug, Clone)]
pub struct Rng {
    parties: usize,
    spec: RngSpec,
    entropy: Mask,
    entropy_fp: Vec<Fingerprint>,
    secret: SecretShare,
    secret_fp: Vec<Fingerprint>,
}

impl Rng {
    /// Creates a new random number generator distributed over several parties,
    /// with the given specification for the result
    pub fn new(parties: usize, spec: &str) -> Result<Self, Error> {
        Ok(Self {
            parties,
            spec: RngSpec::parse(spec)?,
            entropy: Mask::open(RistrettoPoint::identity()),
            entropy_fp: Vec::new(),
            secret: SecretShare(RistrettoPoint::identity()),
            secret_fp: Vec::new(),
        })
    }

    /// Gets this RNG's specification
    pub fn spec(&self) -> String {
        self.spec.to_string()
    }

    /// Gets this RNG's mask value
    pub fn mask(&self) -> &Mask {
        &self.entropy
    }

    /// Adds entropy to this RNG
    pub fn add_entropy(&mut self, party: Fingerprint, share: &Mask) {
        self.entropy += share;
        self.entropy_fp.push(party);
    }

    /// Adds a secret to this RNG
    pub fn add_secret(&mut self, party: Fingerprint, share: &SecretShare) {
        self.secret.0 += share.0;
        self.secret_fp.push(party);
    }

    /// Gets a list of parties that have provided entropy
    pub fn entropy_parties(&self) -> &[Fingerprint] {
        &self.entropy_fp
    }

    /// Gets a list of parties that have revealed secrets
    pub fn secret_parties(&self) -> &[Fingerprint] {
        &self.secret_fp
    }

    /// Tests whether all entropy for generation has been collected
    pub fn is_generated(&self) -> bool {
        self.entropy_parties().len() == self.parties
    }

    /// Tests whether all secrets for revealing the result have been collected
    pub fn is_revealed(&self) -> bool {
        self.secret_parties().len() == self.parties
    }

    /// Generates the result
    pub fn gen(&self, vtmf: &Vtmf) -> u64 {
        let r = vtmf.unmask(&self.entropy, &self.secret);
        let mut reader = vtmf.unmask_random(&r);
        self.spec.gen(&mut reader)
    }
}

#[derive(Clone)]
struct RngSpec(spec::Expr);

impl Display for RngSpec {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for RngSpec {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl RngSpec {
    fn parse(input: &str) -> Result<Self, spec::ParseError> {
        Ok(Self(spec::Expr::parse(input)?))
    }

    fn gen(&self, reader: &mut dyn XofReader) -> u64 {
        self.0.apply(&mut spec::bits(reader))
    }
}

mod spec {
    use digest::XofReader;
    use nom::character::streaming::digit1;
    use std::{
        fmt::{self, Display, Formatter},
        str::FromStr,
    };

    /// An error in parsing an RNG specification
    #[derive(Debug)]
    pub struct ParseError;

    impl From<ParseError> for crate::Error {
        fn from(_: ParseError) -> Self {
            crate::Error::Decoding
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Node {
        Const(u64),
        Die { n: u64, d: u64 },
        Op(Expr, OpKind, Expr),
    }

    impl Display for Node {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            match self {
                Node::Const(k) => write!(f, "{}", k),
                Node::Die { n, d } => write!(f, "{}d{}", n, d),
                Node::Op(l, o, r) => write!(f, "{}{}{}", l, o, r),
            }
        }
    }

    impl Node {
        fn apply(&self, bits: &mut BitIterator) -> u64 {
            match self {
                Node::Const(k) => *k,
                Node::Die { n, d } => {
                    let mut sum = 0u64;
                    for _ in 0..*n {
                        sum += fdr(*d, bits);
                    }
                    sum
                }
                Node::Op(l, o, r) => {
                    let left = l.apply(bits);
                    let right = r.apply(bits);
                    match o {
                        OpKind::Add => left + right,
                        OpKind::Sub => left - right,
                    }
                }
            }
        }

        fn die(n: u64, d: u64) -> Self {
            Node::Die { n, d }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum OpKind {
        Add,
        Sub,
    }

    impl Display for OpKind {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{}", match self {
                OpKind::Add => "+",
                OpKind::Sub => "-",
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Expr(Box<Node>);

    impl Display for Expr {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Expr {
        pub fn parse(input: &str) -> Result<Self, ParseError> {
            expr(input).map(|(_, x)| x).map_err(|_| ParseError)
        }

        pub fn apply(&self, bits: &mut BitIterator) -> u64 {
            self.0.apply(bits)
        }

        fn make(node: Node) -> Self {
            Self(box node)
        }
    }

    named!(number(&str) -> u64,
        ws!(map_res!(digit1, |s: &str| u64::from_str(s)))
    );
    named!(constant(&str) -> Node,
        ws!(map!(number, Node::Const))
    );
    named!(die(&str) -> Node,
        ws!(do_parse!(
            n: number >>
            char!('d') >>
            d: number >>
            (Node::die(n, d))
        ))
    );
    named!(op_kind(&str) -> OpKind,
        ws!(alt!(
            value!(OpKind::Add, char!('+')) |
            value!(OpKind::Sub, char!('-'))
        ))
    );
    named!(op(&str) -> Node,
        ws!(do_parse!(
            l: die >>
            o: op_kind >>
            r: constant >>
            (Node::Op(Expr::make(l), o, Expr::make(r)))
        ))
    );
    named!(expr(&str) -> Expr,
        ws!(alt!(
            map!(op, Expr::make) |
            map!(die, Expr::make)
        ))
    );

    pub struct BitIterator<'a> {
        reader: &'a mut dyn XofReader,
        available: usize,
        current: u64,
    }

    impl<'a> Iterator for BitIterator<'a> {
        type Item = bool;

        fn next(&mut self) -> Option<Self::Item> {
            if self.available == 0 {
                let mut buffer = [0u8; 8];
                self.reader.read(&mut buffer);
                self.current = u64::from_le_bytes(buffer);
                self.available = 64;
            }
            let bit = self.current & 1;
            self.available -= 1;
            self.current >>= 1;
            Some(bit != 0)
        }
    }

    pub fn bits(reader: &mut dyn XofReader) -> BitIterator {
        BitIterator {
            reader,
            available: 0,
            current: 0,
        }
    }

    // [Lu13] Jérémie Lumbroso:
    //          'Optimal Discrete Uniform Generation from Coin Flips, and
    // Applications',          arXiv:1304.1916 [cs.DS], 2013
    fn fdr(d: u64, bits: &mut BitIterator) -> u64 {
        let mut range = 1u64;
        let mut value = 0u64;
        loop {
            let b = bits.next().unwrap() as u64;
            range <<= 1;
            value = value << 1 | b;
            if range >= d {
                if value < d {
                    return value;
                } else {
                    range -= d;
                    value -= d;
                }
            }
        }
    }
}
