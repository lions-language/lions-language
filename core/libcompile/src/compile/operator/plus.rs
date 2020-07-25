use libresult::*;
use libgrammar::token::TokenValue;
use libtype::{Type, TypeValue, TypeAttrubute};
use libtype::function::{FunctionParamData, FunctionParamDataItem
        , splice::FunctionSplice, FindFunctionContext
        , FindFunctionResult, FunctionReturnDataAttr
        , Function};
use libtype::{AddressType, AddressValue};
use libcommon::ptr::{RefPtr};
use crate::compile::{Compile, Compiler, CallFunctionContext};
use crate::address::{Address};
use std::collections::HashSet;

struct Context {
    recycle_addrs: HashSet<AddressValue>
}

impl Context {
    fn push(&mut self, addr: AddressValue) {
        self.recycle_addrs.insert(addr);
    }

    fn remove(&mut self, addr: &AddressValue) {
        self.recycle_addrs.remove(addr);
    }

    fn new() -> Self {
        Self {
            recycle_addrs: HashSet::new()
        }
    }
}

impl<F: Compile> Compiler<F> {
    /*
     * 参数:
     *  typ: 参数的类型
     *  addr: value buffer 中存储的地址信息
     * */
    fn alloc_addr_for_single_type(&mut self, typ: &Type, addr: &Address
        , context: &mut Context)
        -> Address {
        match typ.attr_ref() {
            TypeAttrubute::Move => {
                /*
                 * 如果是 Move, 说明将不归这里管理, 将其所有权移除
                 * */
                self.ref_counter.remove(addr.addr_ref().addr_ref());
                /*
                 * 为了回收地址, 需要添加到回收中
                 * */
                context.push(addr.addr_clone());
            },
            _ => {}
        }
        addr.clone()
    }

    pub fn operator_plus(&mut self, _value: TokenValue) -> DescResult {
        /*
         * 注意:
         *  如果 Move 进去的没有 Move 出来, 尽管由函数内部销毁, 但是编译期, 需要将地址值回收
         *  所以, context 中需要记录哪些地址需要被回收的(只Move进去, 但是没有Move出来的)
         * */
        use libtype::function::consts;
        /*
         * 取出前两个token, 查找第一个函数的 plus 方法
         * */
        let right = self.value_buffer.take_top();
        let left = self.value_buffer.take_top();
        /*
         * 构建 函数参数
         * + 号运算一定只有一个参数
         * */
        let param = FunctionParamData::Single(FunctionParamDataItem::new(right.typ));
        let statement_str = FunctionSplice::get_function_without_return_string_by_type(
            consts::OPERATOR_FUNCTION_NAME, &Some(&param), &Some(&left.typ));
        /*
         * 查找方法声明
         * */
        let func_ptr = match self.function_control.find_function(&FindFunctionContext{
            typ: Some(&left.typ),
            package_typ: None,
            func_str: &statement_str,
            module_str: self.module_stack.current().to_str()
        }, &None) {
            FindFunctionResult::Success(r) => {
                RefPtr::from_ref(r.func)
            },
            FindFunctionResult::Panic(desc) => {
                return DescResult::Error(desc);
            },
            FindFunctionResult::NotFound => {
                unimplemented!();
            }
        };
        let func = func_ptr.as_ref::<Function>();
        let mut context = Context::new();
        /*
         * 为虚拟机准备函数调用的参数 (从后向前入栈, 因为读取的时候是从栈顶向下读取)
         * 1. 判断参数的属性(Move, Ref, Pointer)
         *  决定是存储地址还是存储数据
         * */
        let right_addr = match &func.func_statement.func_param {
            Some(p) => {
                match &p.data {
                    FunctionParamData::Single(param) => {
                        self.alloc_addr_for_single_type(&param.typ, &right.addr, &mut context)
                    },
                    FunctionParamData::Multi(_) => {
                        /*
                         * + 号运算符只能有一个参数, Grammar 在重载时需要进行限制
                         * */
                        panic!("+ should not have multiple parameters");
                    }
                }
            },
            None => {
                panic!("+ at least one parameter is required");
            }
        };
        /*
         * 计算第一个参数的地址 (第一个参数就是 操作数的类型)
         * */
        let left_addr = self.alloc_addr_for_single_type(&left.typ, &left.addr, &mut context);
        /*
         * 从后向前加载, 因为虚拟机加载参数是从前向后的, 那么对于栈, 写入时应该是相反的顺序
         * */
        self.cb.load_variant(&right_addr);
        self.cb.load_variant(&left_addr);
        // println!("{:?}", &right_addr);
        /*
         * 判断返回值是 Move / Ref / Pointer
         * Move: 分配一个新的变量地址, 虚拟机将函数计算后的值与该地址绑定
         * Ref: 分配一个新的引用地址, 引用中的地址, 由 return 字段决定
         * */
        let return_data = &func.func_statement.func_return.data;
        let return_addr = match return_data.typ.attr_ref() {
            TypeAttrubute::Ref => {
                /*
                 * Ref 的情况下, 此时, 虚拟机需要根据给定的地址, 找到数据,
                 * 然后对数据进行修改
                 * */
                let param_addrs = vec![left_addr.clone(), right_addr.clone()];
                let param_index =
                    match &return_data.attr {
                    FunctionReturnDataAttr::RefParamIndex(idx) => {
                        idx
                    },
                    _ => {
                        panic!("returns a reference, 
                            but does not specify which input
                            parameter of the reference");
                    }
                };
                let ref_addr = &param_addrs[*param_index as usize];
                ref_addr.clone()
            },
            TypeAttrubute::Move => {
                let param_addrs = vec![left_addr.addr(), right_addr.addr()];
                match &return_data.attr {
                    FunctionReturnDataAttr::MoveIndex(param_index) => {
                        let ref_addr = &param_addrs[*param_index as usize];
                        /*
                         * 将移入的值移出来了, 所以 不用回收地址 (这个地址还是存在的)
                         * */
                        context.remove(ref_addr);
                    },
                    _ => {}
                }
                /*
                 * 根据类型, 判断是在哪里分配地址
                 * */
                let a = self.address_dispatch.alloc(return_data.typ.to_address_type());
                self.ref_counter.create(a.addr_ref().addr_clone());
                a
            },
            _ => {
                unimplemented!();
            }
        };
        self.cb.call_function(CallFunctionContext{
            func: func,
            return_addr: return_addr.addr_clone()
        });
        /*
         * 回收地址
         * */
        for addr in context.recycle_addrs.iter() {
            self.address_dispatch.recycle_addr(addr.clone());
            // println!("free: {:?}", addr);
        }
        /*
         * 获取返回类型, 将其写入到队列中
         * */
        self.value_buffer.push_with_addr(
            func.func_statement.func_return.data.typ.clone()
            , return_addr);
        DescResult::Success
    }

    /*
    pub fn alloc_addr_for_single_type(&mut self, typ: &Type, addr: &Address)
        -> Address {
        let t = match typ {
            Type::Primeval(t) => {
                t
            },
            _ => {
                unimplemented!();
            }
        };
        match &t.attr {
            TypeAttrubute::Ref => {
                /*
                 * 取 left 指向地址
                 *  如果 left 存储的是地址, 则将地址取出来
                 *  如果 left 存储的是数据, 则将数据地址取出来
                 * */
                match &addr.addr_ref().typ_ref() {
                    AddressType::Static
                    | AddressType::New => {
                        /*
                         * 这种情况下, 本身不指向任何地址, 自身就是数据的地址 (叶子节点)
                         * */
                        self.address_dispatch.prepare_ref(addr.addr())
                    },
                    AddressType::Ref
                    | AddressType::Move => {
                        /*
                         * 这种情况下, 需要将指向的地址取出来 (非叶子节点)
                         * */
                        self.address_dispatch.prepare_ref(addr.direction())
                    },
                    _ => {
                        panic!("should not happend");
                    }
                }
            },
            TypeAttrubute::Move => {
                match &addr.addr_ref().typ_ref() {
                    AddressType::New => {
                        /*
                         * 这种情况下, 本身不指向任何地址, 自身就是数据的地址 (叶子节点)
                         * 将引用计数值清零
                         * */
                        self.address_dispatch.prepare_ref(addr.addr())
                    },
                    AddressType::Move => {
                        /*
                         * 这种情况下, 实际上是指向了一个已有地址
                         *  同时, 将引用计数清零
                         * */
                        self.ref_counter.count_clear_panic(addr.direction_ref().addr_ref());
                        self.address_dispatch.prepare_ref(addr.direction())
                    },
                    AddressType::Static
                    | AddressType::Ref => {
                        /*
                         * 这种情况下, 存储的数据是哟引用, 但是想要移动 => 报错
                         * */
                        panic!("ref / static can't move");
                    },
                    _ => {
                        panic!("should not happend");
                    }
                }
            },
            TypeAttrubute::Pointer => {
                unimplemented!();
            }
        }
    }

    pub fn operator_plus(&mut self, _value: TokenValue) -> DescResult {
        use libtype::function::consts;
        /*
         * 取出前两个token, 查找第一个函数的 plus 方法
         * */
        let right = self.value_buffer.take_top();
        let left = self.value_buffer.take_top();
        /*
         * 构建 函数参数
         * + 号运算一定只有一个参数
         * */
        let param = FunctionParamData::Single(FunctionParamDataItem::new(right.typ));
        let statement_str = FunctionSplice::get_function_without_return_string_by_type(
            consts::OPERATOR_FUNCTION_NAME, &Some(&param), &Some(&left.typ));
        /*
         * 查找方法声明
         * */
        let func_ptr = match self.function_control.find_function(&FindFunctionContext{
            typ: &left.typ,
            func_str: &statement_str,
            module_str: self.module_stack.current().to_str()
        }) {
            FindFunctionResult::Success(r) => {
                RefPtr::from_ref(r.func)
            },
            FindFunctionResult::Panic(desc) => {
                return DescResult::Error(desc);
            }
        };
        let func = func_ptr.as_ref::<Function>();
        /*
         * 为虚拟机准备函数调用的参数 (从后向前入栈, 因为读取的时候是从栈顶向下读取)
         * 1. 判断参数的属性(Move, Ref, Pointer)
         *  决定是存储地址还是存储数据
         * */
        let right_addr = match &func.func_statement.func_param {
            Some(p) => {
                match &p.data {
                    FunctionParamData::Single(param) => {
                        self.alloc_addr_for_single_type(&param.typ, &right.addr)
                    },
                    FunctionParamData::Multi(_) => {
                        /*
                         * + 号运算符只能有一个参数, Grammar 在重载时需要进行限制
                         * */
                        panic!("+ should not have multiple parameters");
                    }
                }
            },
            None => {
                panic!("+ at least one parameter is required");
            }
        };
        /*
         * 计算第一个参数的地址 (第一个参数就是 操作数的类型)
         * */
        let left_addr = self.alloc_addr_for_single_type(&left.typ, &left.addr);
        /*
         * 从后向前加载, 因为虚拟机加载参数是从前向后的, 那么对于栈, 写入时应该是相反的顺序
         * */
        self.cb.load_variant(&right_addr);
        self.cb.load_variant(&left_addr);
        /*
         * 判断返回值是 Move / Ref / Pointer
         * Move: 分配一个新的变量地址, 虚拟机将函数计算后的值与该地址绑定
         * Ref: 分配一个新的引用地址, 引用中的地址, 由 return 字段决定
         * */
        let return_data = &func.func_statement.func_return.data;
        let return_addr = match &return_data.typ {
            Type::Primeval(t) => {
                match &t.attr {
                    TypeAttrubute::Ref => {
                        let param_addrs = vec![left_addr.addr(), right_addr.addr()];
                        let param_index =
                            match &return_data.attr {
                            FunctionReturnDataAttr::RefParamIndex(idx) => {
                                idx
                            },
                            _ => {
                                panic!("returns a reference, 
                                    but does not specify which input
                                    parameter of the reference");
                            }
                        };
                        let ref_addr = &param_addrs[*param_index as usize];
                        self.address_dispatch.alloc_ref(ref_addr.clone())
                    },
                    TypeAttrubute::Move => {
                        let param_addrs = vec![left_addr.addr(), right_addr.addr()];
                        match &return_data.attr {
                            FunctionReturnDataAttr::MoveIndex(param_index) => {
                                let ref_addr = &param_addrs[*param_index as usize];
                                /*
                                 * 将 param_index 对应的值 引用计数 + 1
                                 * */
                                self.ref_counter.count_alloc_panic(ref_addr.addr_ref());
                                /*
                                 * 给出一个返回值, 用于下一次的计算
                                 * */
                                self.address_dispatch.alloc_move(ref_addr.clone())
                            },
                            FunctionReturnDataAttr::Create => {
                                let a = self.address_dispatch.alloc_new();
                                /*
                                 * 添加到引用计数容器中
                                 * */
                                self.ref_counter.create(a.addr_ref().addr());
                                a
                            },
                            _ => {
                                panic!("returns a reference, 
                                    but does not specify which input
                                    parameter of the reference");
                            }
                        }
                    },
                    TypeAttrubute::Pointer => {
                        unimplemented!();
                    }
                }
            },
            _ => {
                unimplemented!();
            }
        };
        self.cb.call_function(CallFunctionContext{
            func: func,
            return_addr: return_addr.addr_ref().addr()
        });
        /*
         * 检测需要被释放的内存
         * */
        /*
        self.ref_counter.iter_zero(|ad| {
            self.cb.free(ad);
        });
        */
        /*
         * 获取返回类型, 将其写入到队列中
         * */
        self.value_buffer.push_with_addr(
            func.func_statement.func_return.data.typ.clone()
            , return_addr);
        DescResult::Success
    }
    */
}

