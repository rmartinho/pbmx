use pbmx_chain::chain::Chain;
use crate::stacks::StackMap;

pub struct State {
    chain: Chain,
    stacks: StackMap,
    block: Vec<Payload>,
}
