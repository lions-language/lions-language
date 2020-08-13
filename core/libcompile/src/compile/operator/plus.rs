use libresult::*;
use libgrammar::token::TokenValue;
use libtype::{Type, TypeAttrubute};
use libtype::function::{FunctionParamData, FunctionParamDataItem
        , splice::FunctionSplice, FindFunctionContext
        , FindFunctionResult, FunctionReturnDataAttr
        , Function, CallFunctionParamAddr
        , CallFunctionReturnData};
use libtype::{AddressType, AddressValue, TypeValue};
use libtype::package::{PackageStr};
use libcommon::ptr::{RefPtr};
use crate::compile::{Compile, Compiler, CallFunctionContext
    , AddressValueExpand};
use crate::address::{Address};
use std::collections::HashSet;

impl<'a, F: Compile> Compiler<'a, F> {
    /*
     * 参数:
     *  typ: 参数的类型
     *  addr: value buffer 中存储的地址信息
     * */
    fn alloc_addr_for_single_type(&mut self, typ: &Type, addr: &Address)
        -> Address {
        match typ.attr_ref() {
            TypeAttrubute::Move => {
                /*
                 * 如果是 Move, 说明将不归这里管理, 将其所有权移除
                 * */
                self.scope_context.ref_counter_remove(addr.addr_ref().addr_ref());
                /*
                 * 为了回收地址, 需要添加到回收中
                 * */
            },
            _ => {}
        }
        addr.clone()
    }

    pub fn operator_plus(&mut self, _value: TokenValue) -> DescResult {
        // println!("plus ...");
        /*
         * 注意:
         *  如果 Move 进去的没有 Move 出来, 尽管由函数内部销毁, 但是编译期, 需要将地址值回收
         *  所以, context 中需要记录哪些地址需要被回收的(只Move进去, 但是没有Move出来的)
         * */
        use libtype::function::consts;
        /*
         * 取出前两个token, 查找第一个函数的 plus 方法
         * */
        let right = self.scope_context.take_top_from_value_buffer();
        let left = self.scope_context.take_top_from_value_buffer();
        let left_addr = left.addr_clone();
        let left_type = left.typ_clone();
        let left_typ_attr = left.typ_attr_clone();
        /*
        println!("left type attr: {:?}, right type attr: {:?}"
            , left.typ_attr_ref(), right.typ_attr_ref());
        */
        /*
         * 1. 将地址中的 scope 值加1, 因为进行函数调用的时候, 会进入一个新的作用域
         * */
        // let left_addr_value = left.addr_ref().addr_ref().clone_with_scope_plus(1);
        let right_addr_value = right.addr_ref().addr_ref().clone_with_scope_plus(1);
        let left_expect_type = self.compile_context.expect_type_ref().clone();
        let left_addr_value = match self.binary_type_match(
            left, &left_expect_type
            , *self.compile_context.is_auto_call_totype_ref()) {
            Ok(addr) => {
                addr
            },
            Err(e) => {
                return e;
            }
        };
        let left_addr_value = left_addr_value.clone_with_scope_plus(1);
        /*
         * 构建 函数参数
         * + 号运算一定只有一个参数
         * */
        let param = FunctionParamData::Multi(vec![
            FunctionParamDataItem::new(left_type.clone(), left_typ_attr.clone())
            , FunctionParamDataItem::new(right.typ_clone(), right.typ_attr_clone())]);
        let statement_str = FunctionSplice::get_function_without_return_string_by_type(
            consts::OPERATOR_PLUS_FUNCTION_NAME, &Some(&param), &Some(&left_type));
        /*
         * 查找方法声明
         * */
        let func_ptr = match self.function_control.find_function(&FindFunctionContext{
            typ: Some(&left_type),
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
                return DescResult::Error(format!("func: {:?} not found", statement_str));
            }
        };
        let func = func_ptr.as_ref::<Function>();
        /*
         * 为虚拟机准备函数调用的参数 (从后向前入栈, 因为读取的时候是从栈顶向下读取)
         * 1. 判断参数的属性(Move, Ref, Pointer)
         *  决定是存储地址还是存储数据
         * */
        /*
        let right_addr = match &func.func_statement.func_param {
            Some(p) => {
                match &p.data {
                    FunctionParamData::Multi(ps) => {
                        for param in ps {
                            self.alloc_addr_for_single_type(&param.typ, &right.addr, &mut context);
                        }
                    },
                    FunctionParamData::Single(param) => {
                        /*
                         * + 号运算必须有两个参数, Grammar 在重载时需要进行限制
                         * */
                        panic!("+ should have multiple parameters");
                    },
                }
            },
            None => {
                panic!("+ at least one parameter is required");
            }
        };
        */
        /*
         * 计算第一个参数的地址 (第一个参数就是 操作数的类型)
         * */
        let left_addr = self.alloc_addr_for_single_type(&left_type, &left_addr);
        let right_addr = self.alloc_addr_for_single_type(&right.typ, &right.addr);
        /*
         * 从后向前加载, 因为虚拟机加载参数是从前向后的, 那么对于栈, 写入时应该是相反的顺序
         * */
        // self.cb.load_variant(&right_addr);
        // self.cb.load_variant(&left_addr);
        // println!("{:?}", &right_addr);
        /*
         * 判断返回值是 Move / Ref / Pointer
         * Move: 分配一个新的变量地址, 虚拟机将函数计算后的值与该地址绑定
         * Ref: 分配一个新的引用地址, 引用中的地址, 由 return 字段决定
         * */
        let mut scope: Option<usize> = None;
        let mut return_is_alloc = false;
        let return_data = &func.func_statement.func_return.data;
        let mut return_addr = match return_data.typ_ref().typ_ref() {
            TypeValue::Empty => {
                /*
                 * 如果返回值是空的, 那么就没有必要分配内存
                 * (不过对于 plus 操作, 一定是要有返回值的, 不会到达这里)
                 * */
                Address::new(AddressValue::new_invalid())
            },
            _ => {
                match return_data.typ_attr_ref() {
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
                    TypeAttrubute::MutRef => {
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
                            },
                            FunctionReturnDataAttr::Create => {
                                return_is_alloc = true;
                            },
                            _ => {}
                        }
                        /*
                         * 根据类型, 判断是在哪里分配地址
                         * note:
                         *  因为该地址需要让虚拟机在分配内存后进行绑定,
                         *  而应该绑定到函数调用的上一个作用域中
                         *  => 所以这里的作用域应该要加1
                         * */
                        scope = Some(1);
                        let a = self.scope_context.alloc_address(return_data.typ.to_address_type(), 1);
                        self.scope_context.ref_counter_create(a.addr_ref().addr_clone());
                        a
                    },
                    TypeAttrubute::CreateRef => {
                        /*
                         * 所有权移动到这一层, 但是属性变成了 MoveRef, 之后就会调用 &move
                         * 相关的方法
                         * */
                        return_is_alloc = true;
                        scope = Some(1);
                        let a = self.scope_context.alloc_address(return_data.typ.to_address_type(), 1);
                        a
                    },
                    _ => {
                        unimplemented!("return type attr: {:?}", return_data.typ_attr_ref());
                    }
                }
            }
        };
        self.call_function_and_ctrl_scope(CallFunctionContext{
            package_str: PackageStr::Empty,
            func: &func,
            param_addrs: Some(vec![CallFunctionParamAddr::Fixed(left_addr_value)
                , CallFunctionParamAddr::Fixed(right_addr_value)]),
            return_data: CallFunctionReturnData::new_with_all(
                return_addr.addr_clone(), return_is_alloc)
        });
        /*
         * 函数调用结束后, 如果之前为 scope 加过1, 需要将返回值地址中的 scope 减掉
         * */
        match scope {
            Some(n) => {
                return_addr.addr_mut().addr_mut_with_scope_minus(n);
            },
            None => {
            }
        };
        /*
         * 回收地址
         * */
        /*
        for addr in context.recycle_addrs.iter() {
            self.scope_context.recycle_address(addr.clone());
            // println!("free: {:?}", addr);
        }
        */
        /*
         * 获取返回类型, 将其写入到队列中
         * */
        if !return_addr.is_invalid() {
            self.scope_context.push_with_addr_typattr_to_value_buffer(
                return_data.typ.clone()
                , return_addr, return_data.typ_attr_ref().clone());
        }
        DescResult::Success
    }
}

