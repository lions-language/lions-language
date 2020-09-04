use libgrammar::grammar::{StructInitContext
    , StructInitFieldContext};
use libgrammar::token::{TokenData};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_struct_init_field_before_expr(&mut self
        , init_context: &mut StructInitContext
        , field_context: &StructInitFieldContext) {
    }

    pub fn process_struct_init_field_after_expr(&mut self
        , init_context: &mut StructInitContext
        , field_context: StructInitFieldContext) {
        // field_context.token
    }
}

