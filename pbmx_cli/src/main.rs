#![warn(missing_docs)]
#![deny(clippy::correctness)]

//! PBMX CLI tool

use crate::error::{Error, Result};
use pbmx_blocks::{
    block::{Block, BlockBuilder, Payload},
    chain::Chain,
};
use pbmx_crypto::{
    group::{Group, Groups},
    keys::{Fingerprint, Keys, PrivateKey, PublicKey},
};
use pbmx_serde::{FromBytes, ToBytes};
use rand::{thread_rng, Rng};
use rustyline::{error::ReadlineError, Editor};
use std::{collections::HashMap, ffi::OsStr, fs, mem, path::Path};

mod error;

struct ParsedChain {
    game: Option<String>,
    group: Option<Group>,
    keys: HashMap<Fingerprint, PublicKey>,
}

struct Secrets {
    sk: Option<PrivateKey>,
}

struct State {
    block: BlockBuilder,
    chain: ParsedChain,
    group: Option<Group>,
    secrets: Secrets,
}

fn main() {
    let chain = read_chain().unwrap();
    if !chain.is_valid() {
        println!("- Broken chain");
        return;
    }
    println!("# Blocks: {}", chain.count());

    let secrets = read_secrets().unwrap();
    if let Some(sk) = &secrets.sk {
        println!("# Private key: {:16}", sk.fingerprint());
    }

    let parsed_chain = parse_chain(&chain);
    if let Some(game) = &parsed_chain.game {
        println!("# Game: {}", game);
    }
    if parsed_chain.keys.len() > 0 {
        print!("# Players: ");
        for k in parsed_chain.keys.keys() {
            print!("{:16} ", k);
        }
        println!();
    }

    let mut state = State {
        block: chain.build_block(),
        group: parsed_chain.group.clone(),
        chain: parsed_chain,
        secrets,
    };
    let mut rl = Editor::<()>::new();
    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_ref());
                let words: Vec<_> = line.split(' ').collect();;
                match words[0] {
                    "start" => do_start(&mut state, &words),
                    "join" => do_join(&mut state, &words),
                    //"stack" => do_stack(&mut state, &words),
                    //"pstack" => do_pstack(&mut state, &words),
                    //"name" => do_name(&mut state, &words),
                    //"shuffle" => do_shuffle(&mut state, &words),
                    ////"shift" => do_shift(&mut state, &words),
                    //"take" => do_take(&mut state, &words),
                    //"pile" => do_pile(&mut state, &words),
                    //"reveal" => do_reveal(&mut state, &words),
                    //"gen" => do_gen(&mut state, &words),
                    //"rand" => do_rand(&mut state, &words),
                    //"msg" => do_msg(&mut state, &words),
                    //"bin" => do_bin(&mut state, &words),
                    //"file" => do_file(&mut state, &words),
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
    save_secrets(&state.secrets).unwrap();
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

fn parse_chain(chain: &Chain) -> ParsedChain {
    let mut game = None;
    let mut group = None;
    let mut keys = HashMap::new();
    for block in chain.blocks() {
        for payload in block.payloads() {
            match payload {
                Payload::DefineGame(n, g) => {
                    game = Some(n.clone());
                    group = Some(g.clone());
                }
                Payload::PublishKey(pk) => {
                    keys.insert(pk.fingerprint(), pk.clone());
                }
                _ => {}
            };
        }
    }
    ParsedChain { game, group, keys }
}

fn read_secrets() -> Result<Secrets> {
    let mut sk = None;
    for entry in fs::read_dir(Path::new("secrets"))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(fname) = entry.path().file_name() {
            if fname != OsStr::new("sk.pbmx") {
                continue;
            }
            sk = Some(PrivateKey::from_bytes(&fs::read(&entry.path())?)?);
        }
    }
    Ok(Secrets { sk })
}

fn save_secrets(secrets: &Secrets) -> Result<()> {
    if let Some(sk) = &secrets.sk {
        fs::write(Path::new("secrets/sk.pbmx"), sk.to_bytes()?)?;
    }
    Ok(())
}

fn ensure_private_key_exists(state: &mut State) {
    let mut rng = thread_rng();

    if state.secrets.sk.is_none() || state.group.is_none() {
        println!(": Generating private key...");
    }

    if state.group.is_none() {
        state.group = Some(rng.sample(&Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        }));
    }

    if state.secrets.sk.is_none() {
        let (sk, pk) = rng.sample(&Keys(state.group.as_ref().unwrap()));
        state.secrets.sk = Some(sk);
        println!("+ Publish key {:16}", pk.fingerprint());
        state.block.add_payload(Payload::PublishKey(pk));
    }
}

fn do_issue(state: &mut State, words: &[&str]) -> Result<()> {
    if words.len() != 1 {
        println!("- Usage: issue");
        return Err(Error::BadCommand);
    }
    ensure_private_key_exists(state);
    let builder = mem::replace(&mut state.block, BlockBuilder::new());
    let block = builder.build(state.secrets.sk.as_ref().unwrap());
    fs::write(
        Path::new(&format!("blocks/{}.pbmx", block.id())),
        block.to_bytes()?,
    )?;
    println!("* Issued block {:16}", block.id());
    Ok(())
}

fn do_start(state: &mut State, words: &[&str]) {
    if words.len() != 2 {
        println!("- Usage: start <game>");
        return;
    }
    let game = words[1].to_string();
    ensure_private_key_exists(state);
    println!("+ Start game '{}'", game);
    let group = state.secrets.sk.as_ref().unwrap().group().clone();
    state.block.add_payload(Payload::DefineGame(game, group));
}

fn do_join(_state: &mut State, words: &[&str]) {
    if words.len() != 1 {
        println!("- Usage: join");
        return;
    }
    println!("+ Join game");
}
