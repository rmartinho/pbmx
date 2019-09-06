use std::iter;

pub trait IteratorEx: Iterator + Sized {
    fn unzip3<A, B, C, FromA, FromB, FromC>(self) -> (FromA, FromB, FromC)
    where
        FromA: Default + Extend<A>,
        FromB: Default + Extend<B>,
        FromC: Default + Extend<C>,
        Self: Iterator<Item = (A, B, C)>,
    {
        let mut r_a = FromA::default();
        let mut r_b = FromB::default();
        let mut r_c = FromC::default();

        for (a, b, c) in self {
            r_a.extend(iter::once(a));
            r_b.extend(iter::once(b));
            r_c.extend(iter::once(c));
        }

        (r_a, r_b, r_c)
    }
}

impl<T: Iterator> IteratorEx for T {}
