use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext};
use crate::compile::scope::{ScopeType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_anonymous_block_start(&mut self) {
        self.scope_context.enter(ScopeType::Block);
        self.cb.enter_scope();
    }

    pub fn process_anonymous_block_end(&mut self) {
        self.scope_context.leave();
        self.cb.leave_scope();
    }
}

