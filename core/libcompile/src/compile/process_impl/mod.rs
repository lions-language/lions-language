use libresult::{DescResult};
use libtype::{Type, TypeAddrType};
use libgrammar::grammar::{ImplStmtContext};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};
use crate::compile::value_buffer::ValueBufferItemContext;
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_impl_stmt(&mut self, context: ImplStmtContext) -> DescResult {
        let find_context = context.find_context();
        let (data_context, define) = find_context.fields_move();
        let typ = Type::from_interface(define, TypeAddrType::Stack);
        self.scope_context.push_with_addr_context_to_value_buffer(
            typ, Address::default(), ValueBufferItemContext::Interface);
        DescResult::Success
    }
}

