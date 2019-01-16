use std::str;

const PART_SEPARATOR: char = ',';
const RANGE_OPERATOR: char = '-';

pub fn parse_index_spec(spec: &str) -> Option<impl Iterator<Item = usize>> {
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
