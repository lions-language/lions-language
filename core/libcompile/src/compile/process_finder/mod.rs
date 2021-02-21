use libresult::{DescResult};
use libtype::instruction::{};
use libgrammar::grammar::{FindInterfaceContext};
use libcommon::consts::{ImportPrefixType};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_find_interface_mid(&mut self, context: &mut FindInterfaceContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_find_interface_end(&mut self, context: &mut FindInterfaceContext) -> DescResult {
        DescResult::Success
    }
}

