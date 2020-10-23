use libtype::{Type, TypeAttrubute, TypeValue};
use libtype::{AddressValue
    , AddressKey, AddressType};
use crate::compile::{Compile, Compiler
    , AddressValueExpand, OwnershipMoveContext
    , AddRefParamAddr};
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
                let addr = AddressValue::new(typ.to_address_type()
                    , AddressKey::new_with_scope_single(index as u64, 0));
                /*
                let length = typ.addr_length();
                let addr = self.scope_context.alloc_address_with_index(
                    typ.to_address_type(), index, 0, length);
                */
                // println!("{:?} <= {:?}", &addr, src_addr.clone_with_scope_plus(1));
                match typ.typ_ref() {
                    TypeValue::Structure(s) => {
                        /*
                         * 移动 自身
                         * */
                        let src = src_addr.clone_with_scope_plus(1);
                        let dst = addr.addr_ref().clone();
                        self.cb.ownership_move(OwnershipMoveContext::new_with_all(
                            dst, src));
                        self.scope_context.recycle_address(src_addr.clone());
                        /*
                        self.cb_ownership_move(
                            dst, src, &value_context);
                        */
                        /*
                         * 移动 成员
                         * */
                        let so = s.struct_obj_ref().pop();
                        if let Some(member) = so.member_ref() {
                            let fields = member.index_field_mapping();
                            for i in 0..(src_addr.addr_ref().length_clone()) {
                                /*
                                 * TODO:
                                 *  owner => 此操作和AddressKey 中的length无关(ownership指令换成index)
                                 * */
                                let mut src = src_addr.clone_with_index_scope_plus(i+1, 1);
                                let dst = addr.addr_ref().clone_with_index_plus(i+1);
                                let field = fields.get(&i).unwrap();
                                if field.typ_attr_ref().is_ref() {
                                    *src.typ_mut() = AddressType::AddrRef;
                                    self.cb.add_ref_param_addr(
                                        AddRefParamAddr::new_with_all(
                                            dst, src));
                                } else if field.typ_attr_ref().is_move() {
                                    *src.typ_mut() = field.typ_ref().to_address_type();
                                    self.cb.ownership_move(OwnershipMoveContext::new_with_all(
                                        dst, src));
                                    /*
                                     * 编译期, funccall 并没有进入一个新的作用域, 所以不需要加 scope
                                     * */
                                    self.scope_context.recycle_address(
                                        src_addr.clone_with_index_plus(i+1));
                                } else {
                                    unimplemented!();
                                }
                            }
                        }
                        s.struct_obj_ref().push(so);
                    },
                    _ => {
                        let src = src_addr.clone_with_scope_plus(1);
                        let dst = addr.addr_ref().clone();
                        self.cb.ownership_move(OwnershipMoveContext::new_with_all(
                            dst, src));
                        self.scope_context.recycle_address(src_addr.clone());
                        /*
                        self.cb_ownership_move(
                            dst, src, &value_context);
                        */
                    }
                }
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
                // self.scope_context.recycle_address(src_addr.clone());
                return addr;
            },
            TypeAttrubute::Ref
            | TypeAttrubute::CreateRef
            | TypeAttrubute::MutRef => {
                /*
                 * 将地址拷贝到作用域中
                 * src: src_addr
                 * dst: index 构建的地址
                 * */
                /*
                let addr = AddressValue::new(AddressType::AddrRef
                    , AddressKey::new_with_scope_single(index as u64, 0));
                match typ.typ_ref() {
                    TypeValue::Structure(s) => {
                        /*
                         * TODO 添加 自身
                         * */
                        /*
                         * 添加 成员
                         * */
                        let so = s.struct_obj_ref().pop();
                        if let Some(member) = so.member_ref() {
                            let fields = member.index_field_mapping();
                            for i in 0..(src_addr.addr_ref().length_clone()) {
                                /*
                                 * TODO:
                                 *  owner => 此操作和AddressKey 中的length无关(ownership指令换成index)
                                 * */
                                let mut src = src_addr.clone_with_index_scope_plus(i+1, 1);
                                let dst = addr.addr_ref().clone_with_index_plus(i+1);
                                let field = fields.get(&i).unwrap();
                                /*
                                if field.typ_attr_ref().is_ref_as_param() {
                                    *src.typ_mut() = AddressType::AddrRef;
                                } else {
                                    *src.typ_mut() = field.typ_ref().to_address_type();
                                }
                                */
                                *src.typ_mut() = AddressType::AddrRef;
                                self.cb.add_ref_param_addr(
                                    AddRefParamAddr::new_with_all(
                                        dst, src));
                            }
                        }
                        s.struct_obj_ref().push(so);
                    },
                    _ => {
                        /*
                         * TODO 添加 自身
                         * */
                    }
                }
                */
            },
            TypeAttrubute::Pointer
            | TypeAttrubute::Empty => {
                unimplemented!();
            }
        }
        src_addr.clone_with_scope_plus(1)
    }
}

