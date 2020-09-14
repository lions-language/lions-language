use libtype::{Type, TypeAttrubute};
use libtype::{AddressValue
    , AddressKey};
use crate::compile::{Compile, Compiler
    , AddressValueExpand, OwnershipMoveContext};
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    /*
     * 参数:
     *  typ: 参数的类型
     *  addr: value buffer 中存储的地址信息
     * */
    pub fn process_param(&mut self, typ: &Type
        , typ_attr: &TypeAttrubute, src_addr: AddressValue
        , index: usize
        , value_context: ValueBufferItemContext)
        -> AddressValue {
        match typ_attr {
            TypeAttrubute::Move => {
                /*
                 * 告诉虚拟机移动地址(交换地址映射),
                 *  主要是为了让实际存储数据的地址有一个可以被找到的标识
                 * 这样虚拟机在作用域结束的时候就可以通过这个标识找到地址, 然后进行释放
                 * */
                // let addr = self.scope_context.alloc_address(AddressType::Stack, 0);
                /*
                let addr = AddressValue::new(typ.to_address_type()
                    , AddressKey::new_with_scope_single(index as u64, 0));
                self.scope_context.use_addr(&addr);
                */
                let length = typ.addr_length();
                let addr = self.scope_context.alloc_address_with_index(
                    typ.to_address_type(), index, 0, length);
                // println!("{:?} => {:?}", &addr, src_addr.clone_with_scope_plus(1));
                self.cb.ownership_move(OwnershipMoveContext::new_with_all(
                    addr.addr_ref().addr_clone(), src_addr.clone_with_scope_plus(1)));
                /*
                 * 如果是移动的变量, 需要将被移动的变量从变量列表中移除
                 * */
                match value_context {
                    ValueBufferItemContext::Variant(v) => {
                        let var_name = v.as_ref::<String>();
                        // println!("remove: {}", var_name);
                        self.scope_context.remove_variant_unchecked(
                            src_addr.addr_ref().scope_clone()
                            , var_name, src_addr.addr_ref());
                    },
                    _ => {}
                }
                /*
                 * 回收索引
                 * */
                // println!("{:?}", src_addr);
                self.scope_context.recycle_address(src_addr.clone());
                return addr.addr();
            },
            TypeAttrubute::Ref
            | TypeAttrubute::CreateRef
            | TypeAttrubute::MutRef => {
                /*
                 * 将地址拷贝到作用域中
                 * src: src_addr
                 * dst: index 构建的地址
                 * */
            },
            TypeAttrubute::Pointer
            | TypeAttrubute::Empty => {
                unimplemented!();
            }
        }
        src_addr.clone_with_scope_plus(1)
    }
}

