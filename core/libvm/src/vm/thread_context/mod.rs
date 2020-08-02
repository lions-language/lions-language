use libtype::{Data};
use scope::context::{ScopeContext};
use crate::memory::stack::RandStack;

pub struct ThreadScope {
    scope_context: ScopeContext,
    data_stack: RandStack<Data>,
}

mod context;
mod scope;
