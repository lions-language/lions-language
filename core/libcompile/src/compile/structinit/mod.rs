use libcommon::ptr::RefPtr;
use libgrammar::grammar::{StructInitContext
    , StructInitFieldContext};
use libgrammar::token::{TokenData};
use libtype::structure::{StructDefine};
use libresult::{DescResult};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_struct_init_start(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        let define = match self.struct_control.find_define(
            self.module_stack.current().name_ref(), init_context.struct_name_ref()) {
            Some(define) => {
                define
            },
            None => {
                return DescResult::Error(
                    format!("struct: {:?} not define", init_context.struct_name_ref()));
            }
        };
        *init_context.define_mut() = RefPtr::from_ref(define);
        DescResult::Success
    }

    pub fn process_struct_init_field_before_expr(&mut self
        , init_context: &mut StructInitContext
        , field_context: StructInitFieldContext) {
        let field_name = extract_token_data!(field_context.name_token().token_data_unchecked(), Id);
        self.scope_context.current_mut_unchecked().enter_structinit_field_stack(field_name);
    }

    pub fn process_struct_init_field_after_expr(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        let mut full_name = String::new();
        self.process_struct_init_splice_full_fieldname(
            &mut full_name);
        // println!("{:?}", full_name);
        let start_addr_index = self.scope_context.current_unchecked().next_new_addr_index();
        let define = init_context.define_ref().as_ref::<StructDefine>();
        let member = match define.member_ref() {
            Some(m) => m,
            None => {
                return DescResult::Error(
                    format!("no member"));
            }
        };
        let field = match member.find_field(&full_name) {
            Some(f) => {
                f
            },
            None => {
                return DescResult::Error(
                    format!("{:?} not find {:?}", init_context.struct_name_ref()
                        , full_name));
            }
        };
        let field_index = field.index_ref();
        /*
         * 根据 field_index 为字段分配地址
         * */
        self.scope_context.current_mut_unchecked().leave_structinit_field_stack();
        DescResult::Success
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

