use libresult::DescResult;
use libgrammar::grammar::{EnumDefineStartContext
    , EnumDefineItemContext, EnumDefineEndContext};
use libtype::enumerate::{EnumerateDefine};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_enum_define_start(&mut self
        , context: EnumDefineStartContext, define: &mut EnumerateDefine) -> DescResult {
        DescResult::Success
    }

    pub fn process_enum_define_item(&mut self
        , context: EnumDefineItemContext, define: &mut EnumerateDefine) -> DescResult {
        DescResult::Success
    }

    pub fn process_enum_define_end(&mut self
        , context: EnumDefineEndContext, define: &mut EnumerateDefine) -> DescResult {
        DescResult::Success
    }
}
