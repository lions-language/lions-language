use libresult::{DescResult};
use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue
    , AddressType, AddressValue
    , Type, TypeAttrubute};
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
        DescResult::Success
    }
}
