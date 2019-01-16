use crate::index_spec::parse_index_spec;
use pbmx_blocks::block::Id;
use std::str::FromStr;

pub type StackRef = String;

pub enum Command {
    Issue,
    Msg(String),
    Bin(String),
    File(String),
    Start(String, usize),
    Join,
    Stack(Vec<u32>),
    StackDown(Vec<u32>),
    Name(StackRef, String),
    Mask(StackRef),
    Shuffle(StackRef, Option<Vec<usize>>),
    Cut(StackRef, Option<usize>),
    Take(StackRef, Vec<usize>),
    Pile(Vec<StackRef>),
    Reveal(StackRef),
    RngBound(u32),
    RngShare(Id),
}

pub struct ParseFailure;

impl FromStr for Command {
    type Err = ParseFailure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.splitn(2, char::is_whitespace).fuse();
        let cmd = it.next();
        let args = it.next();
        match cmd {
            Some("issue") => parse_issue(args),
            Some("msg") => parse_msg(args),
            Some("bin") => parse_bin(args),
            Some("file") => parse_file(args),
            Some("start") => parse_start(args),
            Some("join") => parse_join(args),
            Some("stack") => parse_stack(args),
            Some("stackd") => parse_stack_down(args),
            Some("name") => parse_name(args),
            Some("mask") => parse_mask(args),
            Some("shuffle") => parse_shuffle(args),
            Some("cut") => parse_cut(args),
            Some("take") => parse_take(args),
            Some("pile") => parse_pile(args),
            Some("reveal") => parse_reveal(args),
            Some("gen") => parse_rng_bound(args),
            Some("rand") => parse_rng_share(args),
            _ => Err(ParseFailure),
        }
    }
}

fn parse_issue(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_zero(args, Command::Issue)
}

fn parse_msg(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_string(args, Command::Msg)
}

fn parse_bin(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_string(args, Command::Bin)
}

fn parse_file(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_string(args, Command::File)
}

fn parse_start(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_two(args, |a0, a1| {
        Some(Command::Start(a1.into(), str::parse(a0).ok()?))
    })
}

fn parse_join(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_zero(args, Command::Join)
}

fn parse_stack(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_tokens(args, Command::Stack)
}

fn parse_stack_down(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_tokens(args, Command::StackDown)
}

fn parse_name(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_two(args, |a0, a1| Some(Command::Name(a0.into(), a1.into())))
}

fn parse_mask(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_one(args, |a| Some(Command::Mask(a.into())))
}

fn parse_shuffle(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_one_or_two(args, |a0, a1| {
        let indices = if let Some(a1) = a1 {
            Some(
                parse_index_spec(a1)?.collect::<Vec<_>>(),
            )
        } else {
            None
        };
        Some(Command::Shuffle(a0.into(), indices))
    })
}

fn parse_cut(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_one_or_two(args, |a0, a1| {
        let n = if let Some(a1) = a1 {
            Some(str::parse::<usize>(a1).ok()?)
        } else {
            None
        };
        Some(Command::Cut(a0.into(), n))
    })
}

fn parse_take(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_two(args, |a0, a1| {
        let indices = parse_index_spec(a1)?.collect::<Vec<_>>();
        Some(Command::Take(a0.into(), indices))
    })
}

fn parse_pile(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_one(args, |a| {
        let stacks = a.split_whitespace().map(|s| s.into()).collect::<Vec<_>>();
        Some(Command::Pile(stacks))
    })
}

fn parse_reveal(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_one(args, |a| {
        Some(Command::Reveal(a.into()))
    })
}

fn parse_rng_bound(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_one(args, |a| {
        let n = str::parse::<usize>(a).ok()?;
        Some(Command::RngBound(n as _))
    })
}

fn parse_rng_share(args: Option<&str>) -> Result<Command, ParseFailure> {
    parse_one(args, |a| {
        let id = str::parse::<Id>(a).ok()?;
        Some(Command::RngShare(id))
    })
}

fn parse_string<F>(args: Option<&str>, f: F) -> Result<Command, ParseFailure>
where
    F: Fn(String) -> Command,
{
    args.map(|a| f(a.into())).ok_or(ParseFailure)
}

fn parse_tokens<F>(args: Option<&str>, f: F) -> Result<Command, ParseFailure>
where
    F: Fn(Vec<u32>) -> Command,
{
    args.and_then(|a| {
        let stack = parse_index_spec(a)?;
        Some(f(stack.map(|x| x as _).collect()))
    })
    .ok_or(ParseFailure)
}

fn parse_zero(args: Option<&str>, command: Command) -> Result<Command, ParseFailure> {
    if args.unwrap_or("").is_empty() {
        Ok(command)
    } else {
        Err(ParseFailure)
    }
}

fn parse_one<F>(args: Option<&str>, f: F) -> Result<Command, ParseFailure>
where
    F: Fn(&str) -> Option<Command>,
{
    args.and_then(|a| {
        let mut it = a.split_whitespace();
        let arg = it.next()?;
        if it.next().is_some() {
            return None;
        }
        f(arg)
    })
    .ok_or(ParseFailure)
}

fn parse_one_or_two<F>(args: Option<&str>, f: F) -> Result<Command, ParseFailure>
where
    F: Fn(&str, Option<&str>) -> Option<Command>,
{
    args.and_then(|a| {
        let mut it = a.split_whitespace().fuse();
        let arg0 = it.next()?;
        let arg1 = it.next();
        if it.next().is_some() {
            return None;
        }
        f(arg0, arg1)
    })
    .ok_or(ParseFailure)
}

fn parse_two<F>(args: Option<&str>, f: F) -> Result<Command, ParseFailure>
where
    F: Fn(&str, &str) -> Option<Command>,
{
    args.and_then(|a| {
        let mut it = a.split_whitespace();
        let arg0 = it.next()?;
        let arg1 = it.next()?;
        if it.next().is_some() {
            return None;
        }
        f(arg0, arg1)
    })
    .ok_or(ParseFailure)
}
