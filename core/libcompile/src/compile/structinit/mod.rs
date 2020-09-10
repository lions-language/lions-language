use libcommon::ptr::{HeapPtr, RefPtr};
use libgrammar::grammar::{StructInitContext
    , StructInitFieldContext};
use libgrammar::token::{TokenData};
use libtype::{Type, TypeAddrType
    , AddressKey, AddressValue};
use libtype::structure::{StructDefine
    , StructField};
use libresult::{DescResult};
use crate::compile::{Compile, Compiler
    , OwnershipMoveContext, AddRefParamAddr};
use crate::compile::address::Address;
use crate::compile::scope::{StructInitField
    , StructInit};
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_struct_init_start(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        let de = match self.struct_control.find_define(
            self.module_stack.current().name_ref(), init_context.struct_name_ref()) {
            Some(define) => {
                define
            },
            None => {
                return DescResult::Error(
                    format!("struct: {:?} not define", init_context.struct_name_ref()));
            }
        };
        *init_context.define_mut() = de.clone();
        let define = de.pop::<StructDefine>();
        let member_length = define.member_length();
        let addr_index =
            if self.scope_context.current_mut_unchecked().structinit_is_empty() {
            /*
             * 最顶级 struct init
             * */
            let start_addr_index =
                self.scope_context.alloc_continuous_address(1+member_length);
            // println!("{:?}, {}", member_length, start_addr_index+1);
            /*
            /*
             * 为struct分配地址
             * */
            let typ = Type::from_struct(define, TypeAddrType::Stack);
            let addr = Address::new(AddressValue::new(
                typ.to_address_type(), AddressKey::new_with_all(
                    start_addr_index as u64, 0, 0, 0, member_length)));
            self.scope_context.push_with_addr_context_typattr_to_value_buffer(
                typ
                , addr, ValueBufferItemContext::Structure
                , init_context.desc_ctx_ref().typ_attr_clone());
            */
            start_addr_index
        } else {
            let index = self.scope_context.current_unchecked()
                .get_current_structinit_field_stack_unchecked()
                .field_ref().as_ref::<StructField>().index_clone();
            let value = self.scope_context.current_mut_unchecked()
                .get_structinit_stack_top_item_unchecked();
            value.addr_index_clone() + 1 + index
        };
        // println!("{}, {}", addr_index, member_length);
        self.scope_context.current_mut_unchecked().enter_structinit_stack(
            StructInit::new_with_all(de.clone(), addr_index, member_length));
        de.push(define);
        DescResult::Success
    }

    pub fn process_struct_init_end(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        let value = self.scope_context.current_mut_unchecked().leave_structinit_stack().unwrap();
        let typ = Type::from_struct(value.define_clone(), TypeAddrType::Stack);
        let addr = Address::new(AddressValue::new(
            typ.to_address_type(), AddressKey::new_with_all(
                value.addr_index_clone() as u64, 0, 0, 0, value.addr_length_clone())));
        // println!("{:?}", addr);
        self.scope_context.push_with_addr_context_typattr_to_value_buffer(
            typ
            , addr, ValueBufferItemContext::Structure
            , init_context.desc_ctx_ref().typ_attr_clone());
        DescResult::Success
    }

    pub fn process_struct_init_field_before_expr(&mut self
        , init_context: &mut StructInitContext
        , field_context: StructInitFieldContext) -> DescResult {
        let field_name = extract_token_data!(field_context.name_token().token_data_unchecked(), Id);
        let len = self.scope_context.current_unchecked().get_structinit_field_stack_len();
        self.scope_context.current_mut_unchecked().enter_structinit_field_stack(
            StructInitField::new_with_all(
                field_name, RefPtr::new_null()));
        let mut full_name = String::new();
        self.process_struct_init_splice_full_fieldname(
            &mut full_name);
        // println!("{}", full_name);
        let value = self.scope_context.current_mut_unchecked()
            .get_structinit_stack_top_item_unchecked();
        // println!("{}: {:?}", full_name, value.define_ref());
        let start_addr_index = value.addr_index_clone();
        let define = value.define_ref().pop::<StructDefine>();
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
        let field_ptr = RefPtr::from_ref(field);
        value.define_ref().push(define);
        *self.scope_context.current_mut_unchecked()
            .get_current_mut_structinit_field_stack_unchecked()
            .field_mut() = field_ptr;
        DescResult::Success
    }

    pub fn process_struct_init_field_after_expr(&mut self
        , init_context: &mut StructInitContext) -> DescResult {
        let value = self.scope_context.current_mut_unchecked()
            .get_structinit_stack_top_item_unchecked();
        let start_addr_index = value.addr_index_clone();
        let struct_field = self.scope_context.current_unchecked()
            .get_current_structinit_field_stack_unchecked()
            .field_ref().as_ref::<StructField>();
        /*
         * 1. 从 value buffer 中获取数据
         * 2. 对得到的struct_field地址索引进行赋值操作
         * */
        let field_index = struct_field.index_clone();
        let field_addr_index = start_addr_index + 1 + field_index;
        let field_typ = struct_field.typ_clone();
        let field_typ_attr = struct_field.typ_attr_clone();
        let addr = Address::new(AddressValue::new(
            field_typ.to_address_type(), AddressKey::new_with_all(
                field_addr_index as u64, 0, 0, 0, field_typ.addr_length())));
        let value_item = self.scope_context.take_top_from_value_buffer();
        // println!("{:?}", &value);
        let value_typ = value_item.typ_ref().clone();
        let value_typ_attr = value_item.typ_attr_clone();
        let value_addr = value_item.addr_ref().addr_clone();
        let value_context = value_item.context_clone();
        /*
         * 检测typ attr是否匹配
         * */
        if field_typ_attr != value_typ_attr {
            return DescResult::Error(
                format!("left typ_attr is {:?}, right typ_attr is {:?}"
                    , field_typ_attr, value_typ_attr));
        }
        if let ValueBufferItemContext::Structure = &value_context {
        } else {
            if field_typ_attr.is_move() {
                /*
                 * 移动
                 * */
                // println!("move: {:?} <= {:?}", addr.addr_ref(), value_addr);
                self.cb.ownership_move(OwnershipMoveContext::new_with_all(
                    addr.addr().addr(), value_addr.clone()));
            } else if field_typ_attr.is_ref() {
                // println!("add_ref: {:?} <= {:?}", addr.addr_ref(), value_addr);
                self.cb.add_ref_param_addr(
                    AddRefParamAddr::new_with_all(
                        addr.addr().addr(), value_addr.clone()));
            } else {
                unimplemented!();
            }
        }
        match &value_context {
            ValueBufferItemContext::Variant(v) => {
                let var_name = v.as_ref::<String>();
                self.scope_context.remove_variant_unchecked(
                    value_addr.addr_ref().scope_clone()
                    , var_name);
            },
            _ => {
            }
        }
        /*
         * 根据 field_index 为字段分配地址
         * */
        self.scope_context.current_mut_unchecked().leave_structinit_field_stack();
        // let s = self.scope_context.current_mut_unchecked().leave_structinit_field_stack();
        // println!("{:?}: {:?}, {:?}", s.unwrap().name_ref(), field_addr_index, value_addr);
        DescResult::Success
    }
    
    fn process_struct_init_splice_full_fieldname(
        &mut self, full_name: &mut String) {
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
        // println!("{}, {:?}", n-1, name);
        full_name.push('.');
        full_name.push_str(name);
    }
}
