use crate::{indices::display_indices, state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::{
    chain::{Block, BlockVisitor, ChainVisitor, Id, PayloadVisitor},
    crypto::{
        keys::PublicKey,
        vtmf::{
            InsertProof, Mask, MaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
            Stack,
        },
    },
};

pub fn run(_: &ArgMatches, cfg: &Config) -> Result<()> {
    let state = State::read(false)?;

    state.chain.visit(&mut LogPrinter(&state, cfg));

    Ok(())
}

struct LogPrinter<'a>(&'a State, &'a Config);

impl<'a> ChainVisitor for LogPrinter<'a> {}

impl<'a> BlockVisitor for LogPrinter<'a> {
    fn visit_block(&mut self, block: &Block) {
        print!("{}", format!("{:16}", block.id()).yellow());

        print!(" {}", "by".blue().bold());
        let fp = block.signer();
        if let Some(n) = self.0.names.get(&fp) {
            print!(" {}", n);
        } else {
            print!(" {:16}", fp);
        }

        if !block.parent_ids().is_empty() {
            print!(" {}", "ack".blue());
            for id in block.parent_ids() {
                print!(" {:16}", id);
            }
        }
        println!();

        for payload in block.payloads() {
            self.visit_payload(block, payload);
        }
    }
}

impl<'a> PayloadVisitor for LogPrinter<'a> {
    fn visit_publish_key(&mut self, _: &Block, name: &str, pk: &PublicKey) {
        println!("    {} {} {}", "key".green().bold(), name, pk.fingerprint());
    }

    fn visit_open_stack(&mut self, _: &Block, stack: &Stack) {
        println!("    {} {:16}", "stack".green().bold(), stack.id());
    }

    fn visit_mask_stack(&mut self, _: &Block, id: Id, stack: &Stack, _: &[MaskProof]) {
        println!(
            "    {} {:16} \u{21AC} {:16}",
            "mask".green().bold(),
            id,
            stack.id()
        );
    }

    fn visit_shuffle_stack(&mut self, _: &Block, id: Id, stack: &Stack, _: &ShuffleProof) {
        println!(
            "    {} {:16} \u{224B} {:16}",
            "shuffle".green().bold(),
            id,
            stack.id()
        );
    }

    fn visit_shift_stack(&mut self, _: &Block, id: Id, stack: &Stack, _: &ShiftProof) {
        println!(
            "    {} {:16} \u{21CB} {:16}",
            "cut".green().bold(),
            id,
            stack.id()
        );
    }

    fn visit_take_stack(&mut self, _: &Block, id1: Id, indices: &[usize], id2: Id) {
        println!(
            "    {} {:16}{} \u{219B} {:16}",
            "take".green().bold(),
            id1,
            display_indices(indices),
            id2
        );
    }

    fn visit_pile_stack(&mut self, _: &Block, ids: &[Id], id2: Id) {
        println!(
            "    {} {:16?} \u{21A3} {:16}",
            "pile".green().bold(),
            ids,
            id2
        );
    }

    fn visit_insert_stack(&mut self, _: &Block, id1: Id, id2: Id, stack: &Stack, _: &InsertProof) {
        println!(
            "    {} {:16} {:16} {:16}",
            "insert".green().bold(),
            id1,
            id2,
            stack.id()
        );
    }

    fn visit_name_stack(&mut self, _: &Block, id: Id, name: &str) {
        println!("    {} {:16} {}", "name".green().bold(), id, name);
    }

    fn visit_publish_shares(
        &mut self,
        _: &Block,
        id: Id,
        _: &[SecretShare],
        _: &[SecretShareProof],
    ) {
        println!("    {} {:16}", "secret".green().bold(), id);
    }

    fn visit_random_spec(&mut self, _: &Block, id: &str, spec: &str) {
        println!("    {} {}: {}", "rng".green().bold(), id, spec);
    }

    fn visit_random_entropy(&mut self, _: &Block, id: &str, _: &Mask) {
        println!("    {} {}", "rng entropy".green().bold(), id);
    }

    fn visit_random_reveal(&mut self, _: &Block, id: &str, _: &SecretShare, _: &SecretShareProof) {
        println!("    {} {}", "rng reveal".green().bold(), id);
    }

    fn visit_bytes(&mut self, _: &Block, bytes: &[u8]) {
        println!(
            "    {} {}",
            "bytes".green().bold(),
            String::from_utf8_lossy(bytes)
        );
    }
}
