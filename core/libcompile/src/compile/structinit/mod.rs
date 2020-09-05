use libgrammar::grammar::{StructInitContext
    , StructInitFieldContext};
use libgrammar::token::{TokenData};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_struct_init_field_before_expr(&mut self
        , init_context: &mut StructInitContext
        , field_context: StructInitFieldContext) {
        let field_name = extract_token_data!(field_context.name_token().token_data_unchecked(), Id);
        self.scope_context.current_mut_unchecked().enter_structinit_field_stack(field_name);
    }

    pub fn process_struct_init_field_after_expr(&mut self
        , init_context: &mut StructInitContext) {
        let mut full_name = String::new();
        self.process_struct_init_splice_full_fieldname(
            &mut full_name);
        println!("{:?}", full_name);
        self.scope_context.current_mut_unchecked().leave_structinit_field_stack();
    }
    
    fn process_struct_init_splice_full_fieldname(
        &self, full_name: &mut String) {
        self.process_struct_init_splice_full_fieldname_inner(
            "", 0, true, full_name);
    }

    fn process_struct_init_splice_full_fieldname_inner(
        &self, name: &str, n: usize, is_first: bool, full_name: &mut String) {
        match self.scope_context.current_unchecked()
            .get_last_n_structinit_field_stack(n) {
            Some(v) => {
                self.process_struct_init_splice_full_fieldname_inner(v, n+1, false, full_name);
                if is_first {
                    return;
                }
                // println!("{}, {:?}", n-1, name);
                full_name.push('.');
                full_name.push_str(name);
            },
            None => {
                full_name.push_str(name);
                return;
            }
        }
    }
}

