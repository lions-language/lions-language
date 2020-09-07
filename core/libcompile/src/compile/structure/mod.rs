use libtype::structure::{StructDefine
    , StructMember};
use libgrammar::grammar::{StructDefineFieldContext};
use libgrammar::token::{TokenData};
use crate::compile::{Compile, Compiler
    , TypeTokenExpand};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_struct_define_start(&mut self, _: &mut StructDefine) {
    }

    pub fn process_struct_define_field(&mut self, context: StructDefineFieldContext
        , define: &mut StructDefine) {
        let (name_token, type_token, typ_attr) = context.fields_move();
        let name_data = name_token.token_data_unchecked();
        let name = extract_token_data!(name_data, Id);
        match define.member_mut() {
            Some(m) => {
                m.add(name, self.to_type(type_token), typ_attr);
            },
            None => {
                let mut m = StructMember::new();
                m.add(name, self.to_type(type_token), typ_attr);
                *define.member_mut() = Some(m);
            }
        }
    }

    pub fn process_struct_define_end(&mut self, define: StructDefine) {
        // define.print();
        self.struct_control.add_define(
            self.module_stack.current().name_clone()
            , define.name_ref().clone()
            , define);
    }
}

