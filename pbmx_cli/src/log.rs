use crate::{error::Result, state::State};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_chain::{
    block::Block,
    chain::{Chain, ChainVisitor},
    Id,
};
use pbmx_curve::{
    keys::PublicKey,
    vtmf::{
        Mask, MaskProof, PrivateMaskProof, SecretShare, SecretShareProof, ShiftProof, ShuffleProof,
        Vtmf,
    },
};

pub fn log(_: &ArgMatches) -> Result<()> {
    let state = State::read()?;

    state.chain.visit(&mut LogPrinter(&state.vtmf));

    Ok(())
}

struct LogPrinter<'a>(&'a Vtmf);

impl<'a> ChainVisitor for LogPrinter<'a> {
    fn visit_block(&mut self, chain: &Chain, block: &Block) {
        println!("{}", format!("{:16}", block.id()).yellow().bold());

        if !block.parent_ids().is_empty() {
            print!("  {}", "ack".blue());
            for id in block.parent_ids() {
                print!(" {:16}", id);
            }
            println!();
        }

        println!("  {} {:16}", "signer".blue(), block.signer());

        println!("  {}", "payloads".blue());
        for payload in block.payloads() {
            self.visit_payload(chain, block, payload);
        }
    }

    fn visit_publish_key(&mut self, _: &Chain, _: &Block, pk: &PublicKey) {
        println!("    {} {:16}", "key".green(), pk.fingerprint());
    }

    fn visit_open_stack(&mut self, _: &Chain, _: &Block, _stack: &[Mask]) {
        println!("    {} {}", "stack[pub]".green(), "<???>");
    }

    fn visit_private_stack(
        &mut self,
        _: &Chain,
        _: &Block,
        id: Id,
        stack: &[Mask],
        _: &[PrivateMaskProof],
    ) {
        println!("    {} {:16} \u{2283} {:16}", "stack[sec]".green(), id, Id::of(&stack.to_vec()).unwrap());
    }

    fn visit_mask_stack(&mut self, _: &Chain, _: &Block, id: Id, stack: &[Mask], _: &[MaskProof]) {
        println!("    {} {:16} \u{21AC} {:16}", "mask".green(), id, Id::of(&stack.to_vec()).unwrap());
    }

    fn visit_shuffle_stack(
        &mut self,
        _: &Chain,
        _: &Block,
        id: Id,
        stack: &[Mask],
        _: &ShuffleProof,
    ) {
        println!("    {} {:16} \u{224B} {:16}", "shuffle".green(), id, Id::of(&stack.to_vec()).unwrap());
    }

    fn visit_shift_stack(&mut self, _: &Chain, _: &Block, id: Id, stack: &[Mask], _: &ShiftProof) {
        println!("    {} {:16} \u{21CB} {:16}", "cut".green(), id, Id::of(&stack.to_vec()).unwrap());
    }

    fn visit_name_stack(&mut self, _: &Chain, _: &Block, id: Id, name: &str) {
        println!("    {} {:16} {}", "name".green(), id, name);
    }

    fn visit_publish_shares(
        &mut self,
        _: &Chain,
        _: &Block,
        id: Id,
        _: &[SecretShare],
        _: &[SecretShareProof],
    ) {
        println!("    {} {:16}", "secret".green(), id);
    }

    fn visit_start_random(&mut self, _: &Chain, _: &Block, id: Id, n: u64) {
        println!("    {} {:16} < {}", "random".green(), id, n);
    }

    fn visit_random_share(&mut self, _: &Chain, _: &Block, id: Id, _: &Mask) {
        println!("    {} {:16}", "entropy".green(), id);
    }

    fn visit_bytes(&mut self, _: &Chain, _: &Block, bytes: &[u8]) {
        println!("    {} {}", "bytes".green(), String::from_utf8_lossy(bytes));
    }
}
