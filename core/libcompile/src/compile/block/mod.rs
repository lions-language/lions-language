use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{BlockDefineContext};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext};
use crate::compile::scope::{ScopeType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_anonymous_block_start(&mut self) {
        self.scope_context.enter(ScopeType::Block);
        self.cb_enter_scope();
    }

    pub fn process_anonymous_block_end(&mut self) {
        self.scope_context.leave();
        self.cb_leave_scope();
    }

    pub fn process_block_define_start(&mut self, define_context: &mut BlockDefineContext) {
    }

    pub fn process_block_define_end(&mut self, define_context: &mut BlockDefineContext) {
    }
}

