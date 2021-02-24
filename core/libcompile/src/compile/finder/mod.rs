use libresult::{DescResult};
use libgrammar::grammar::{FindInterfaceContext
    , FindInterfacePrefixContext
    , FindInterfaceEndContext};
use libgrammar::token::{TokenData};
use libcommon::consts::{ImportPrefixType};
use libcommon::ptr::{HeapPtr};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_find_interface_prefix(&mut self, prefix_context: FindInterfacePrefixContext
                                         , context: &mut FindInterfaceContext) -> DescResult {
        if context.context_ref().is_null() {
            let id = extract_token_data!(prefix_context.value().token_data_unchecked(), Id);
            *context.context_mut() = HeapPtr::alloc(id);
        } else {
            unreachable!("prefix be called only once");
        }
        DescResult::Success
    }

    pub fn process_find_interface_end(&mut self, end_context: FindInterfaceEndContext
                                      , context: &mut FindInterfaceContext) -> DescResult {
        DescResult::Success
    }
}

