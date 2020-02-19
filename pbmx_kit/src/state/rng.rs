use crate::crypto::{
    keys::Fingerprint,
    vtmf::{Mask, SecretShare, Vtmf},
};
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use digest::XofReader;
use std::fmt::{self, Debug, Display, Formatter};

/// A distributed random number generator
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
    pub fn new(parties: usize, spec: &str) -> Result<Self, spec::ParseError> {
        Ok(Self {
            parties,
            spec: RngSpec::parse(spec)?,
            entropy: Mask::open(RistrettoPoint::identity()),
            entropy_fp: Vec::new(),
            secret: RistrettoPoint::identity(),
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
        self.secret += share;
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
        self.0.apply(reader)
    }
}

mod spec {
    use digest::XofReader;
    use nom::{digit, types::CompleteStr};
    use std::{
        fmt::{self, Display, Formatter},
        iter,
        str::FromStr,
    };

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
        Die { n: u64, d: u64, max: u64 },
        Op(Expr, OpKind, Expr),
    }

    impl Display for Node {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            match self {
                Node::Const(k) => write!(f, "{}", k),
                Node::Die { n, d, .. } => write!(f, "{}d{}", n, d),
                Node::Op(l, o, r) => write!(f, "{}{}{}", l, o, r),
            }
        }
    }

    impl Node {
        fn apply(&self, reader: &mut dyn XofReader) -> u64 {
            match self {
                Node::Const(k) => *k,
                Node::Die { n, d, max } => {
                    let mut sum = 0u64;
                    for _ in 0..*n {
                        loop {
                            let mut buf = [0u8; 8];
                            reader.read(&mut buf);
                            let x = u64::from_be_bytes(buf);
                            if x < *max {
                                sum += x % *d;
                                break;
                            }
                        }
                    }
                    sum
                }
                Node::Op(l, o, r) => {
                    let left = l.apply(reader);
                    let right = r.apply(reader);
                    match o {
                        OpKind::Add => left + right,
                        OpKind::Sub => left - right,
                    }
                }
            }
        }

        fn die(n: u64, d: u64) -> Self {
            let max = iter::repeat(d)
                .scan(1u64, |s, x| {
                    let (r, overflow) = s.overflowing_mul(x);
                    if overflow {
                        None
                    } else {
                        *s = r;
                        Some(*s)
                    }
                })
                .last()
                .unwrap();
            Node::Die { n, d, max }
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
            expr(CompleteStr(input))
                .map(|(_, x)| x)
                .map_err(|_| ParseError)
        }

        pub fn apply(&self, reader: &mut dyn XofReader) -> u64 {
            self.0.apply(reader)
        }

        fn make(node: Node) -> Self {
            Self(box node)
        }
    }

    named!(number(CompleteStr) -> u64,
        ws!(map_res!(digit, |s: CompleteStr| u64::from_str(s.0)))
    );
    named!(constant(CompleteStr) -> Node,
        ws!(map!(number, Node::Const))
    );
    named!(die(CompleteStr) -> Node,
        ws!(do_parse!(
            n: number >>
            char!('d') >>
            d: number >>
            (Node::die(n, d))
        ))
    );
    named!(op_kind(CompleteStr) -> OpKind,
        ws!(alt!(
            value!(OpKind::Add, char!('+')) |
            value!(OpKind::Sub, char!('-'))
        ))
    );
    named!(op(CompleteStr) -> Node,
        ws!(do_parse!(
            l: die >>
            o: op_kind >>
            r: constant >>
            (Node::Op(Expr::make(l), o, Expr::make(r)))
        ))
    );
    named!(expr(CompleteStr) -> Expr,
        ws!(alt!(
            map!(op, Expr::make) |
            map!(die, Expr::make)
        ))
    );
}
