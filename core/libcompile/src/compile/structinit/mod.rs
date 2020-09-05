use libcommon::ptr::RefPtr;
use libgrammar::grammar::{StructInitContext
    , StructInitFieldContext};
use libgrammar::token::{TokenData};
use libtype::structure::{StructDefine};
use libresult::{DescResult};
use crate::compile::{Compile, Compiler};
use crate::compile::scope::{StructInitField};

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
        self.scope_context.current_mut_unchecked().enter_structinit_stack();
        DescResult::Success
    }

    pub fn process_struct_init_end(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        match self.scope_context.current_mut_unchecked()
            .leave_structinit_stack() {
            Some(v) => {
                match self.scope_context.current_mut_unchecked()
                    .get_current_mut_structinit_stack() {
                    Some(va) => {
                        *va += v;
                    },
                    None => {
                        /*
                         * 到达最外层
                         * */
                        println!("{:?}", v);
                    }
                }
            },
            None => {
            }
        }
        DescResult::Success
    }

    pub fn process_struct_init_field_before_expr(&mut self
        , init_context: &mut StructInitContext
        , field_context: StructInitFieldContext) {
        let field_name = extract_token_data!(field_context.name_token().token_data_unchecked(), Id);
        let len = self.scope_context.current_unchecked().get_structinit_field_stack_len();
        self.scope_context.current_mut_unchecked().enter_structinit_field_stack(
            StructInitField::new_with_all(
                field_name, init_context.define_clone()
                , 0));
    }

    pub fn process_struct_init_field_after_expr(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        let mut full_name = String::new();
        self.process_struct_init_splice_full_fieldname(
            &mut full_name);
        // println!("{:?}", full_name);
        /*
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
        */
        /*
         * 根据 field_index 为字段分配地址
         * */
        let s = self.scope_context.current_mut_unchecked().leave_structinit_field_stack();
        println!("{:?}, {}", full_name, s.unwrap().count_ref());
        /*
         * 添加最外层
         * */
        match self.scope_context.current_mut_unchecked()
            .get_current_mut_structinit_stack() {
            Some(va) => {
                *va += 1;
            },
            None => {
            }
        }
        /*
        if s.as_ref().unwrap().count_ref() > &0 {
            println!("{:?}, {}", full_name, s.unwrap().count_ref());
        }
        */
        // let len = self.scope_context.current_unchecked().get_structinit_field_stack_len();
        // println!("{:?}, {}", s, len);
        DescResult::Success
    }
    
    fn process_struct_init_splice_full_fieldname(
        &mut self, full_name: &mut String) {
        // println!("{}", self.scope_context.current_unchecked()
        //     .get_last_n_structinit_field_stack(0).unwrap());
        self.process_struct_init_splice_full_fieldname_inner(
            "", 0, true, full_name);
    }

    fn process_struct_init_splice_full_fieldname_inner(
        &mut self, name: &str, n: usize, is_first: bool, full_name: &mut String) {
        let mut field = match self.scope_context.current_mut_unchecked()
            .get_last_n_mut_structinit_field_stack(n) {
            Some(v) => {
                RefPtr::from_ref(v)
            },
            None => {
                full_name.push_str(name);
                return;
            }
        };
        let v = field.as_mut::<StructInitField>();
        self.process_struct_init_splice_full_fieldname_inner(
            v.name_ref(), n+1, false, full_name);
        if is_first {
            return;
        }
        /*
         * 每次递归向上查找的时候, 需要将每一级的 count 都加上1
         * */
        *v.count_mut() += 1;
        // println!("{}, {:?}", n-1, name);
        full_name.push('.');
        full_name.push_str(name);
    }
}

