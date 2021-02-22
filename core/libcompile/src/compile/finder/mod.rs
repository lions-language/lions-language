use libresult::{DescResult};
use libgrammar::grammar::{FindInterfaceContext};
use libcommon::consts::{ImportPrefixType};
use libcommon::ptr::{HeapPtr};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

struct ModPrefix {
    context: String
}

impl ModPrefix {
    fn push(&mut self, s: &str) {
        self.context.push_str(s);
    }

    fn new() -> Self {
        Self {
            context: String::new()
        }
    }
}

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_find_interface_mid(&mut self, context: &mut FindInterfaceContext) -> DescResult {
        match context.context_ref() {
            Some(ctx) => {
                let mut prefix = ctx.pop::<ModPrefix>();
                prefix.push(context.seque_ref().last().unwrap());
                ctx.push(prefix);
            },
            None => {
                *context.context_mut() = Some(HeapPtr::alloc(ModPrefix::new()));
            }
        }
        DescResult::Success
    }

    pub fn process_find_interface_end(&mut self, context: &mut FindInterfaceContext) -> DescResult {
        DescResult::Success
    }
}

