use crate::{
    chain::Id,
    crypto::{hash::TranscriptHashable, vtmf::Mask},
    proto,
    serde::{vec_from_proto, vec_to_proto, Proto},
    Result,
};
use merlin::Transcript;
use std::{
    borrow::{Borrow, BorrowMut},
    iter::FromIterator,
    ops::{Deref, DerefMut, Index, IndexMut},
};

/// A masked stack
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Stack(pub(crate) Vec<Mask>);

impl Proto for Stack {
    type Message = proto::Stack;

    fn to_proto(&self) -> Result<proto::Stack> {
        Ok(proto::Stack {
            masks: vec_to_proto(&self.0)?,
        })
    }

    fn from_proto(m: &proto::Stack) -> Result<Self> {
        Ok(Stack(vec_from_proto(&m.masks)?))
    }
}

impl Stack {
    /// Gets an ID for this stack
    pub fn id(&self) -> Id {
        Id::of(self, b"pbmx-stack-id")
    }
}

impl TranscriptHashable for Stack {
    fn append_to_transcript(&self, t: &mut Transcript, label: &'static [u8]) {
        b"stack".append_to_transcript(t, label);
        self.0.append_to_transcript(t, b"$");
    }
}

impl<T> From<T> for Stack
where
    Vec<Mask>: From<T>,
{
    fn from(t: T) -> Self {
        Self(Vec::from(t))
    }
}

impl Deref for Stack {
    type Target = [Mask];

    fn deref(&self) -> &[Mask] {
        self.0.deref()
    }
}

impl DerefMut for Stack {
    fn deref_mut(&mut self) -> &mut [Mask] {
        self.0.deref_mut()
    }
}

impl<T> AsRef<T> for Stack
where
    Vec<Mask>: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}

impl<T> AsMut<T> for Stack
where
    Vec<Mask>: AsMut<T>,
{
    fn as_mut(&mut self) -> &mut T {
        self.0.as_mut()
    }
}

impl<T> Borrow<T> for Stack
where
    Vec<Mask>: Borrow<T>,
{
    fn borrow(&self) -> &T {
        self.0.borrow()
    }
}

impl<T> BorrowMut<T> for Stack
where
    Vec<Mask>: BorrowMut<T>,
{
    fn borrow_mut(&mut self) -> &mut T {
        self.0.borrow_mut()
    }
}

impl<T> FromIterator<T> for Stack
where
    Vec<Mask>: FromIterator<T>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self(Vec::from_iter(iter))
    }
}

impl IntoIterator for Stack {
    type IntoIter = <Vec<Mask> as IntoIterator>::IntoIter;
    type Item = <Vec<Mask> as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> Extend<T> for Stack
where
    Vec<Mask>: Extend<T>,
{
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = T>,
    {
        self.0.extend(iter)
    }
}

impl<I> Index<I> for Stack
where
    Vec<Mask>: Index<I>,
{
    type Output = <Vec<Mask> as Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        self.0.index(index)
    }
}

impl<I> IndexMut<I> for Stack
where
    Vec<Mask>: IndexMut<I>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}
