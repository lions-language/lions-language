use libresult::{DescResult};
use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue
    , AddressType, AddressValue
    , Type, TypeAttrubute};
use libtype::instruction::{UpdateRefParamAddr};
use libgrammar::grammar::{VarStmtContext, VarUpdateStmtContext};
use crate::address::Address;
use crate::compile::{Compile, Compiler, OwnershipMoveContext};
use crate::compile::scope::vars::Variant;
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_var_stmt_start(&mut self) {
    }

    pub fn handle_var_stmt_end(&mut self, context: VarStmtContext) -> DescResult {
        let is_exist_equal = *context.is_exist_equal_ref();
        /*
         * 1. 为变量在栈上分配一个空的地址 (如果存在`=`, 再改变该地址)
         * 2. 将变量写入到作用域中
         * */
        let name = extract_token_data!(
           context.id_token().token_data().expect("should not happend")
           , Id);
        if !is_exist_equal {
            self.scope_context.add_variant(name
                , Variant::new(
                    Address::new(AddressValue::new_invalid())
                    , Type::new_null()
                    , TypeAttrubute::default()));
            return DescResult::Success;
        }
        /*
         * 存在 `=` (赋予初始值)
         *  1. 从栈顶获取表达式的计算结果
         *  2. 判断等号的右边的计算结果是否是变量, 如果是变量, 需要更新 vars 中对应的值为 Move
         *      读取变量的时候, 如果值为 Move, 需要报错
         * */
        let value = match self.scope_context.take_top_from_value_buffer() {
            Ok(v) => v,
            Err(e) => {
                return e;
            }
        };
        // println!("{:?}", &value);
        let typ = value.typ_ref().clone();
        let typ_attr = value.typ_attr_ref().clone();
        let src_addr = value.addr_ref().addr_clone();
        // println!("{:?}", typ_attr);
        /*
        self.scope_context.add_variant(name
            , Variant::new_with_all(
                Address::new(src_addr.clone()), typ, typ_attr));
        */
        // println!("{:?}", typ_attr);
        match value.context_ref() {
            ValueBufferItemContext::Structure => {
                self.scope_context.add_variant(name
                    , Variant::new(
                        Address::new(src_addr), typ, typ_attr));
                return DescResult::Success;
            },
            _ => {}
        }
        match &typ_attr {
            TypeAttrubute::Move
            | TypeAttrubute::CreateRef => {
                /*
                 * 告诉虚拟机移动地址(交换地址映射),
                 *  主要是为了让实际存储数据的地址有一个可以被找到的标识
                 * 这样虚拟机在作用域结束的时候就可以通过这个标识找到地址, 然后进行释放
                 * */
                let addr = self.scope_context.alloc_address(typ.to_address_type(), 0
                    , typ.addr_length());
                // println!("var {} define, alloc addr: {:?}", name, addr);
                self.scope_context.add_variant(name
                    , Variant::new(
                        Address::new(addr.addr_clone()), typ, typ_attr));
                self.cb.ownership_move(OwnershipMoveContext::new_with_all(
                    addr.addr().addr(), src_addr.clone()));
                /*
                 * 如果是移动的变量, 需要将被移动的变量从变量列表中移除
                 * */
                match value.context_ref() {
                    ValueBufferItemContext::Variant(v) => {
                        let var_name = v.as_ref::<String>();
                        // println!("remove {}", var_name);
                        self.scope_context.remove_variant_unchecked(
                            value.addr_ref().addr_ref().addr_ref().scope_clone()
                            , var_name, src_addr.addr_ref());
                    },
                    _ => {}
                }
                /*
                 * 回收索引
                 * */
                // println!("{:?}", src_addr);
                self.scope_context.recycle_address(src_addr);
            },
            TypeAttrubute::Ref
            | TypeAttrubute::MutRef => {
                /*
                 * 将实际存储数据的地址存储到 Variant 对象中 (也就是 src_addr)
                 * */
                self.scope_context.add_variant(name
                    , Variant::new(
                        Address::new(src_addr), typ, typ_attr));
            },
            TypeAttrubute::Pointer
            | TypeAttrubute::Empty => {
                unimplemented!();
            }
        }
        DescResult::Success
    }

    pub fn handle_var_update_stmt(&mut self, context: VarUpdateStmtContext) -> DescResult {
        let name = context.fields_move();
        /*
         * 等号右边的
         * */
        let right_value = match self.scope_context.take_top_from_value_buffer() {
            Ok(v) => v,
            Err(e) => {
                return e;
            }
        };
        /*
         * 等号左边的
         * */
        let left_value = match self.scope_context.take_top_from_value_buffer() {
            Ok(v) => v,
            Err(e) => {
                return e;
            }
        };
        /*
         * 变量是引用类型 => 更新编译期的映射 (将变量原来指向的内存更改为现在指向的内存)
         * 变量是移动类型 => 1. 将变量原来指向的内存释放掉(告诉虚拟机释放);
         *                   2. 为变量绑定新的地址(编译期)
         * */
        let (var_typ, var_addr, var_typ_attr, var_package_type, var_package_str, var_context)
            = left_value.fields_move();
        let (expr_typ, expr_addr, expr_typ_attr, expr_package_type, expr_package_str, expr_context)
            = right_value.fields_move();
        if var_typ.typ_ref() != expr_typ.typ_ref() {
            return DescResult::Error(
                format!("typ not match! left typ: {:?}, but right typ: {:?}"
                    , var_typ, expr_typ));
        }
        if var_typ_attr.is_ref_as_assign() {
            if !expr_typ_attr.is_ref_as_assign() {
                return DescResult::Error(
                    format!("typ attr not match! left typ attr: {:?}, but right typ attr: {:?}"
                        , var_typ_attr, expr_typ_attr));
            }
            match name {
                Some(var_name) => {
                    /*
                     * 左边是变量名
                     * */
                    let mut var_ptr = match self.scope_context.find_variant_mut(&var_name) {
                        Some(v) => v,
                        None => {
                            return DescResult::Error(
                                format!("var: {:?} is not found", var_name));
                        }
                    };
                    let var = var_ptr.as_mut::<Variant>();
                    *var.addr_mut() = expr_addr;
                },
                None => {
                    /*
                     * 左边是对象成员的 point access
                     *  => 告诉虚拟机换一下地址
                     * */
                    self.cb.update_ref_param_addr(
                        UpdateRefParamAddr::new_with_all(
                            var_addr.addr().addr(), expr_addr.addr_clone()));
                }
            }
        } else if var_typ_attr.is_move_as_assign() {
            if !expr_typ_attr.is_move_as_assign() {
                return DescResult::Error(
                    format!("not match! left typ attr: {:?}, but right typ attr: {:?}"
                        , var_typ_attr, expr_typ_attr));
            }
        } else {
            unimplemented!();
        }
        DescResult::Success
    }
}
