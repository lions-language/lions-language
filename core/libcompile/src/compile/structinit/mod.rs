use libcommon::ptr::RefPtr;
use libgrammar::grammar::{StructInitContext
    , StructInitFieldContext};
use libgrammar::token::{TokenData};
use libtype::{Type, TypeAddrType
    , AddressKey, AddressValue};
use libtype::structure::{StructDefine};
use libresult::{DescResult};
use crate::compile::{Compile, Compiler};
use crate::compile::address::Address;
use crate::compile::scope::{StructInitField
    , StructInit};
use crate::compile::value_buffer::{ValueBufferItemContext};

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
        let addr_index =
            if self.scope_context.current_mut_unchecked().structinit_is_empty() {
            /*
             * 最顶级 struct init
             * */
            let member_length = define.member_length();
            let start_addr_index =
                self.scope_context.alloc_continuous_address(1+member_length);
            // println!("{:?}, {}", member_length, start_addr_index+1);
            /*
             * 为最外层struct分配地址, 并将其写入到 value buffer 中
             * */
            let typ = Type::from_struct(define, TypeAddrType::Stack);
            let addr = Address::new(AddressValue::new(
                typ.to_address_type(), AddressKey::new_with_all(
                    start_addr_index as u64, 0, 0, 0, member_length)));
            self.scope_context.push_with_addr_context_typattr_to_value_buffer(
                typ
                , addr, ValueBufferItemContext::Structure
                , init_context.desc_ctx_ref().typ_attr_clone());
            start_addr_index+1
        } else {
            0
        };
        self.scope_context.current_mut_unchecked().enter_structinit_stack(
            StructInit::new_with_all(RefPtr::from_ref(define), addr_index));
        DescResult::Success
    }

    pub fn process_struct_init_end(&mut self
        , _init_context: &mut StructInitContext) -> DescResult {
        self.scope_context.current_mut_unchecked().leave_structinit_stack();
        DescResult::Success
    }

    pub fn process_struct_init_field_before_expr(&mut self
        , init_context: &mut StructInitContext
        , field_context: StructInitFieldContext) {
        let field_name = extract_token_data!(field_context.name_token().token_data_unchecked(), Id);
        let len = self.scope_context.current_unchecked().get_structinit_field_stack_len();
        self.scope_context.current_mut_unchecked().enter_structinit_field_stack(
            StructInitField::new_with_all(
                field_name, 0));
    }

    pub fn process_struct_init_field_after_expr(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        let mut full_name = String::new();
        self.process_struct_init_splice_full_fieldname(
            &mut full_name);
        // println!("{:?}", full_name);
        let value = self.scope_context.current_mut_unchecked()
            .get_structinit_stack_top_item_unchecked();
        let start_addr_index = value.addr_index_clone();
        let define = value.define_ref().as_ref::<StructDefine>();
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
        // println!("{:?}", field);
        let field_index = field.index_ref();
        /*
         * 根据 field_index 为字段分配地址
         * */
        let s = self.scope_context.current_mut_unchecked().leave_structinit_field_stack();
        println!("{:?}, {}, {}", full_name, s.unwrap().count_ref(), start_addr_index);
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

