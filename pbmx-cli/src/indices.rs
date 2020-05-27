use std::{
    fmt::{self, Display, Formatter},
    str,
};

const PART_SEPARATOR: char = ',';
const RANGE_OPERATOR: char = '-';

pub fn parse_indices(spec: &str) -> Option<impl Iterator<Item = usize>> {
    spec.split(PART_SEPARATOR)
        .map(|part| {
            let mut ends = part.split(RANGE_OPERATOR);
            let begin: usize = str::parse(ends.next()?).ok()?;
            let endp = ends.next();
            let end: usize = if let Some(e) = endp {
                str::parse(e).ok()?
            } else {
                begin
            };
            Some(begin..=end)
        })
        .map(|r| r.ok_or(()))
        .collect::<Result<Vec<_>, _>>()
        .ok()
        .map(|v| v.into_iter().flatten())
}

pub fn display_indices<'a>(indices: &'a [usize]) -> impl Display + 'a {
    DisplayIndices(indices)
}

struct DisplayIndices<'a>(&'a [usize]);

impl<'a> Display for DisplayIndices<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut first = true;
        let mut last_in_seq = None;
        let mut unfinished_seq = false;
        write!(f, "[")?;
        for i in self.0.iter() {
            if let Some(last) = last_in_seq {
                if last + 1 == *i {
                    unfinished_seq = true;
                } else {
                    if unfinished_seq {
                        write!(f, "-{}", last)?;
                        unfinished_seq = false;
                    }
                    write!(f, " {}", i)?;
                }
            } else {
                if !first {
                    write!(f, " ")?;
                }
                write!(f, "{}", i)?;
            }
            last_in_seq = Some(i);
            first = false;
        }
        if unfinished_seq {
            let last = last_in_seq.unwrap();
            write!(f, "-{}", last)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}
