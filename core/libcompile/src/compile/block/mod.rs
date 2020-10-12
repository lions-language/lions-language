use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{BlockDefineContext};
use libresult::DescResult;
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext};
use crate::compile::scope::{ScopeType};
use crate::define::{DefineObject};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_anonymous_block_start(&mut self) {
        self.scope_context.enter(ScopeType::Block);
        self.cb_enter_scope();
    }

    pub fn process_anonymous_block_end(&mut self) {
        self.scope_context.leave();
        self.cb_leave_scope();
    }

    pub fn process_block_define_start(&mut self, define_context: &mut BlockDefineContext)
        -> DescResult {
        self.scope_context.enter(ScopeType::Block);
        self.cb.enter_block_define(define_context);
        DescResult::Success
    }

    pub fn process_block_define_end(&mut self, define_context: &mut BlockDefineContext)
        -> DescResult {
        self.scope_context.leave();
        let addr = self.cb.leave_block_define(DefineObject::new(define_context.define_obj_clone()));
        *define_context.define_addr_mut() = addr;
        DescResult::Success
    }
}

