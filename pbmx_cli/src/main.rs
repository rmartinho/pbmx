#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX CLI tool

use crate::error::{Error, Result};
use pbmx_blocks::{
    block::{Block, BlockBuilder, Id, Payload::*},
    chain::Chain,
};
use pbmx_crypto::{
    group::{Group, Groups},
    keys::{Keys, PrivateKey},
    vtmf::Mask,
};
use pbmx_serde::{FromBytes, ToBytes};
use rand::{thread_rng, Rng};
use rustyline::{error::ReadlineError, Editor};
use std::{ffi::OsStr, fs, mem, path::Path};

mod chain_parser;
use self::chain_parser::ParsedChain;
mod error;
mod index_spec;

struct State {
    block: BlockBuilder,
    chain: ParsedChain,
    group: Option<Group>,
    private_key: Option<PrivateKey>,
    stacks: Vec<(Id, Vec<Mask>)>,
}

fn main() {
    let chain = read_chain().unwrap();
    println!("# Blocks: {}", chain.count());

    let sk = read_secrets().unwrap();
    if let Some(sk) = &sk {
        println!("# Private key: {:16}", sk.fingerprint());
    }

    let parsed_chain = chain_parser::parse_chain(&chain, &sk).unwrap();
    parsed_chain.print_out();

    let mut state = State {
        block: chain.build_block(),
        group: parsed_chain.group().cloned(),
        stacks: parsed_chain.stacks().into(),
        chain: parsed_chain,
        private_key: sk,
    };
    let mut rl = Editor::<()>::new();
    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_ref());
                let words: Vec<_> = line.split(' ').filter(|s| !s.is_empty()).collect();;
                match words[0] {
                    "start" => do_start(&mut state, &words),
                    "join" => do_join(&mut state, &words),
                    "stack" => do_stack(&mut state, &words),
                    //"pstack" => do_pstack(&mut state, &words),
                    //"name" => do_name(&mut state, &words),
                    //"shuffle" => do_shuffle(&mut state, &words),
                    ////"shift" => do_shift(&mut state, &words),
                    //"take" => do_take(&mut state, &words),
                    //"pile" => do_pile(&mut state, &words),
                    //"reveal" => do_reveal(&mut state, &words),
                    //"gen" => do_gen(&mut state, &words),
                    //"rand" => do_rand(&mut state, &words),
                    "msg" => do_msg(&mut state, &words),
                    "bin" => do_bin(&mut state, &words),
                    "file" => do_file(&mut state, &words),
                    "issue" => {
                        if let Ok(()) = do_issue(&mut state, &words) {
                            break;
                        }
                    }
                    "quit" => break,
                    "" => {}
                    _ => println!("- Unknown command: {}", line),
                }
            }
            Err(ReadlineError::Interrupted) => break,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                println!("- Error: {:?}", err);
                break;
            }
        }
    }
    save_secrets(&state.private_key).unwrap();
}

fn read_chain() -> Result<Chain> {
    let mut chain = Chain::default();
    for entry in fs::read_dir(Path::new("blocks"))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(ext) = entry.path().extension() {
            if ext != OsStr::new("pbmx") {
                continue;
            }
            let block = Block::from_bytes(&fs::read(&entry.path())?)?;
            chain.add_block(block);
        }
    }
    Ok(chain)
}

fn read_secrets() -> Result<Option<PrivateKey>> {
    let mut sk = None;
    for entry in fs::read_dir(Path::new("secrets"))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(fname) = entry.path().file_name() {
            if fname != OsStr::new("me.sk") {
                continue;
            }
            sk = Some(PrivateKey::from_bytes(&fs::read(&entry.path())?)?);
        }
    }
    Ok(sk)
}

fn save_secrets(sk: &Option<PrivateKey>) -> Result<()> {
    if let Some(sk) = &sk {
        fs::write(Path::new("secrets/me.sk"), sk.to_bytes()?)?;
    }
    Ok(())
}

fn ensure_private_key_exists(state: &mut State) {
    let mut rng = thread_rng();

    if state.group.is_none() {
        println!(": Generating Schnorr group...");

        let group = rng.sample(&Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        });
        println!(
            "+ Group \u{2124}q, |q| = {}",
            group.order().significant_bits()
        );
        state.block.add_payload(PublishGroup(group.clone()));
        state.group = Some(group);
    }

    if state.private_key.is_none() {
        let (sk, pk) = rng.sample(&Keys(state.group.as_ref().unwrap()));
        state.private_key = Some(sk);
        println!("+ Publish key {:16}", pk.fingerprint());
        state.block.add_payload(PublishKey(pk));
    }
}

fn do_issue(state: &mut State, words: &[&str]) -> Result<()> {
    if words.len() != 1 {
        println!("- Usage: issue");
        return Err(Error::BadCommand);
    }
    ensure_private_key_exists(state);
    let builder = mem::replace(&mut state.block, BlockBuilder::new());
    let block = builder.build(state.private_key.as_ref().unwrap());
    fs::write(
        Path::new(&format!("blocks/{:16}.pbmx", block.id())),
        block.to_bytes()?,
    )?;
    println!("* Issued block {:16}", block.id());
    eprintln!("{:?}", block);
    Ok(())
}

fn do_start(state: &mut State, words: &[&str]) {
    if words.len() != 3 {
        println!("- Usage: start <game> <parties>");
        return;
    }
    let game = words[1].to_string();
    let parties = str::parse(words[2]).unwrap();
    println!("+ Start game '{}' {}p", game, parties);
    state.block.add_payload(DefineGame(game, parties));
    ensure_private_key_exists(state);
}

fn do_join(state: &mut State, words: &[&str]) {
    if words.len() != 1 {
        println!("- Usage: join");
        return;
    }
    ensure_private_key_exists(state);
    println!("+ Join game");
}

fn do_stack(state: &mut State, words: &[&str]) {
    if words.len() != 2 {
        println!("- Usage: stack <tokens>");
        return;
    }
    let vtmf = state.chain.vtmf();
    if vtmf.is_none() {
        println!("- Exchanging keys first");
        return;
    }
    let vtmf = state.chain.vtmf().unwrap();
    let stack: Vec<_> = index_spec::parse_index_spec(words[1])
        .map(|t| vtmf.mask_open(&t.into()))
        .collect();
    let payload = CreateStack(stack.clone());
    state.stacks.push((payload.id(), stack));
    state.block.add_payload(payload);
    println!(
        "+ Stack {} [{:16}]",
        state.stacks.len(),
        state.stacks[state.stacks.len() - 1].0
    );
}

fn do_msg(state: &mut State, words: &[&str]) {
    if words.len() < 2 {
        println!("- Usage: msg <text>...");
        return;
    }
    let mut bytes = Vec::new();
    bytes.extend(words[1].as_bytes());
    for w in &words[2..] {
        bytes.extend(&[b' ']);
        bytes.extend(w.as_bytes());
    }
    println!("+ Message: {} bytes", bytes.len());
    state.block.add_payload(Bytes(bytes));
}

fn do_bin(state: &mut State, words: &[&str]) {
    if words.len() != 2 {
        println!("- Usage: bin <base64>");
        return;
    }
    let bytes = base64::decode(words[1]).unwrap();
    println!("+ Message: {} bytes", bytes.len());
    state.block.add_payload(Bytes(bytes));
}

fn do_file(state: &mut State, words: &[&str]) {
    if words.len() != 2 {
        println!("- Usage: file <path>");
        return;
    }
    let bytes = fs::read(Path::new(words[1])).unwrap();
    println!("+ Message: {} bytes", bytes.len());
    state.block.add_payload(Bytes(bytes));
}
