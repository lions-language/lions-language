use libtype::structure::{StructDefine};
use libgrammar::grammar::{StructDefineFieldContext};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_struct_define_start(&mut self, define: &mut StructDefine) {
    }

    pub fn process_struct_define_field(&mut self, context: StructDefineFieldContext
        , define: &mut StructDefine) {
    }

    pub fn process_struct_define_end(&mut self, define: StructDefine) {
        self.struct_control.add_define(
            self.module_stack.current().name_clone()
            , define.name_ref().clone()
            , define);
    }
}

