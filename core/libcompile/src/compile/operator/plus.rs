use libresult::*;
use libgrammar::token::TokenValue;
use libtype::{Type, TypeAttrubute};
use libtype::function::{FunctionParamData, FunctionParamDataItem
        , splice::FunctionSplice, FindFunctionContext
        , FindFunctionResult, FunctionReturnDataAttr
        , Function};
use libcommon::ptr::{RefPtr};
use crate::compile::{Compile, Compiler, CallFunctionContext};
use crate::compile::address_dispatch::{Address, AddressType};

impl<F: Compile> Compiler<F> {
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
                    AddressType::Ref => {
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
                unimplemented!();
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
                    FunctionParamData::Multi(params) => {
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
                        self.address_dispatch.alloc_new()
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
         * 获取返回类型, 将其写入到队列中
         * */
        self.value_buffer.push_with_addr(
            func.func_statement.func_return.data.typ.clone()
            , return_addr);
        DescResult::Success
    }
}

