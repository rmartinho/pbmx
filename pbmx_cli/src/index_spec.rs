use std::str;

const PART_SEPARATOR: char = ',';
const RANGE_OPERATOR: char = '-';

pub fn parse_index_spec<'a>(spec: &'a str) -> impl Iterator<Item = u32> + 'a {
    spec.split(PART_SEPARATOR).flat_map(|part| {
        let mut ends = part.split(RANGE_OPERATOR);
        let begin = str::parse(ends.next().unwrap()).unwrap();
        let endp = ends.next();
        let end = if let Some(e) = endp {
            str::parse(e).unwrap()
        } else {
            begin
        };
        begin..=end
    })
}
