use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use digest::XofReader;
use pbmx_kit::crypto::{
    keys::Fingerprint,
    vtmf::{Mask, SecretShare, Vtmf},
};
use std::fmt::{self, Debug, Display, Formatter};

#[derive(Debug)]
pub struct Rng {
    parties: usize,
    spec: RngSpec,
    entropy: Mask,
    entropy_fp: Vec<Fingerprint>,
    secret: SecretShare,
    secret_fp: Vec<Fingerprint>,
}

impl Rng {
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

    pub fn spec(&self) -> String {
        self.spec.to_string()
    }

    pub fn mask(&self) -> &Mask {
        &self.entropy
    }

    pub fn add_entropy(&mut self, party: Fingerprint, share: &Mask) {
        self.entropy += share;
        self.entropy_fp.push(party);
    }

    pub fn add_secret(&mut self, party: Fingerprint, share: &SecretShare) {
        self.secret += share;
        self.secret_fp.push(party);
    }

    pub fn entropy_parties(&self) -> &[Fingerprint] {
        &self.entropy_fp
    }

    pub fn secret_parties(&self) -> &[Fingerprint] {
        &self.secret_fp
    }

    pub fn is_generated(&self) -> bool {
        self.entropy_parties().len() == self.parties
    }

    pub fn is_revealed(&self) -> bool {
        self.secret_parties().len() == self.parties
    }

    pub fn gen(&self, vtmf: &Vtmf) -> u64 {
        let r = vtmf.unmask(&self.entropy, &self.secret);
        let mut reader = vtmf.unmask_random(&r);
        self.spec.gen(&mut reader)
    }
}

pub struct RngSpec(spec::Expr);

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
        Ok(Self(spec::parse_expr(input)?))
    }

    fn gen(&self, reader: &mut XofReader) -> u64 {
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
            crate::Error::InvalidData
        }
    }

    pub trait Node: Display {
        fn apply(&self, reader: &mut XofReader) -> u64;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Const(u64);

    impl Display for Const {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Node for Const {
        fn apply(&self, _: &mut XofReader) -> u64 {
            self.0
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Die {
        n: u64,
        d: u64,
        max: u64,
    }

    impl Display for Die {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{}d{}", self.n, self.d)
        }
    }

    impl Die {
        fn new(n: u64, d: u64) -> Self {
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
            Self { n, d, max }
        }
    }

    impl Node for Die {
        fn apply(&self, reader: &mut XofReader) -> u64 {
            let mut sum = 0u64;
            for _ in 0..self.n {
                loop {
                    let mut buf = [0u8; 8];
                    reader.read(&mut buf);
                    let x = u64::from_be_bytes(buf);
                    if x < self.max {
                        sum += x % self.d;
                        break;
                    }
                }
            }
            sum
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Op(Die, OpKind, Const);

    impl Display for Op {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{}{}{}", self.0, self.1, self.2)
        }
    }

    impl Node for Op {
        fn apply(&self, reader: &mut XofReader) -> u64 {
            let left = self.0.apply(reader);
            let right = self.2.apply(reader);
            match self.1 {
                OpKind::Add => left + right,
                OpKind::Sub => left - right,
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
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

    pub type Expr = Box<dyn Node + 'static>;

    pub fn parse_expr(input: &str) -> Result<Expr, ParseError> {
        expr(CompleteStr(input))
            .map(|(_, x)| x)
            .map_err(|_| ParseError)
    }

    fn make_expr<T: Node + 'static>(t: T) -> Expr {
        box t
    }

    named!(number(CompleteStr) -> u64,
        ws!(map_res!(digit, |s: CompleteStr| u64::from_str(s.0)))
    );
    named!(constant(CompleteStr) -> Const,
        ws!(map!(number, Const))
    );
    named!(die(CompleteStr) -> Die,
        ws!(do_parse!(
            n: number >>
            char!('d') >>
            d: number >>
            (Die::new(n, d))
        ))
    );
    named!(op_kind(CompleteStr) -> OpKind,
        ws!(alt!(
            value!(OpKind::Add, char!('+')) |
            value!(OpKind::Sub, char!('-'))
        ))
    );
    named!(op(CompleteStr) -> Op,
        ws!(do_parse!(
            l: die >>
            o: op_kind >>
            r: constant >>
            (Op(l, o, r))
        ))
    );
    named!(expr(CompleteStr) -> Expr,
        ws!(alt!(
            map!(op, make_expr) |
            map!(die, make_expr)
        ))
    );
}
