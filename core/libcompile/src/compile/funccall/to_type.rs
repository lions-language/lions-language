use libtype::{
    TypeAttrubute, TypeValue
    , Type, AddressKey};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionParamData
    , CallFunctionParamAddr, Function, splice::FunctionSplice
    , FunctionReturnDataAttr, FunctionParamDataItem
    , CallFunctionReturnData};
use libtype::instruction::{AddRefParamAddr};
use libtype::{AddressValue};
use libresult::*;
use libcommon::ptr::RefPtr;
use crate::compile::{Compile, Compiler
    , CallFunctionContext, value_buffer::ValueBufferItem
    , AddressValueExpand};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn binary_type_match(&mut self, input_value: ValueBufferItem, expect_typ: &Type
        , is_auto_call_totype: bool)
        -> Result<(Type, TypeAttrubute, AddressValue), DescResult> {
        // let input_typ = input_value.typ_ref();
        let (input_typ, input_addr, input_typ_attr, input_package_type
            , input_package_str, input_value_context) = input_value.fields_move();
        if !is_auto_call_totype {
            /*
             * 不需要自动调用 to_#type => 直接返回输入的地址
             * */
            return Ok((input_typ, input_typ_attr, input_addr.addr()));
        }
        // println!("{:?}", input_addr);
        let et = expect_typ.typ_ref();
        let it = input_typ.typ_ref();
        if !et.is_any() {
            /*
             * 不是 any 的情况下才需要判断类型
             * */
            if !(it == et) {
                /*
                 * 类型不匹配
                 *  查找需要转换的函数是否存在
                 *  比如说: expect_typ 是 string 类型, 那么查找 input_typ 中是否存在 to_string
                 *  方法
                 * */
                /*
                 * 1. 拼接 期望的方法名
                 * */
                let func_name = FunctionSplice::get_to_type_by_type(expect_typ);
                let param = FunctionParamData::Single(FunctionParamDataItem::new(
                    input_typ.clone(), input_typ_attr.clone()));
                let expect_func_str = FunctionSplice::get_function_without_return_string_by_type(
                    &func_name, &Some(&param), &Some(&input_typ));
                // println!("{:?}", expect_func_str);
                /*
                 * 查找方法
                 * */
                let find_func_context = FindFunctionContext {
                    func_name: &func_name,
                    typ: Some(&input_typ),
                    package_typ: input_package_type.as_ref(),
                    func_str: &expect_func_str,
                    module_str: self.module_stack.current().name_ref()
                };
                let (exists, handle) = self.function_control.is_exists(&find_func_context);
                if !exists {
                    return Err(DescResult::Error(format!(
                    "expect type: {:?}, but found type: {:?}, and not find func: {} in {:?}"
                    , et, it, expect_func_str, it)));
                }
                /*
                 * 方法存在 => 调用方法
                 * */
                let h = Some(handle);
                let func_res = self.function_control.find_function(&find_func_context, &h);
                let func_ptr = match func_res {
                    FindFunctionResult::Success(r) => {
                        RefPtr::from_ref(r.func)
                    },
                    _ => {
                        panic!("should not happend: find function error");
                    }
                };
                let func = func_ptr.as_ref::<Function>();
                /*
                 * 将参数地址中的 scope 加1, 告诉虚拟机要从上一个作用域中查找
                 * */
                /*
                 * 参数可能是引用也可能是移动
                 * */
                let mut ref_param_addr = None;
                let mut param_move = None;
                let param_addrs = vec![CallFunctionParamAddr::Fixed(
                    input_addr.addr_ref().clone_with_scope_plus(1))];
                if input_typ_attr.is_move_as_param() {
                    param_move = Some((input_typ.clone(), input_typ_attr.clone()
                            , input_addr.addr_clone()
                            , 0
                            , input_value_context));
                } else if input_typ_attr.is_ref_as_param() {
                    ref_param_addr = Some(
                        AddRefParamAddr::new_with_all(
                        AddressKey::new_with_all(0, 0, 0, 0, 0)
                        , input_addr.addr_ref().clone_with_scope_plus(1)));
                } else {
                    unimplemented!();
                }
                let func_statement = func.func_statement_ref();
                let return_data = &func_statement.func_return.data;
                let mut scope: Option<usize> = None;
                let mut return_is_alloc = false;
                let return_addr = match return_data.typ_ref().typ_ref() {
                    TypeValue::Empty => {
                        /*
                         * 如果返回值是空的, 那么就没有必要分配内存
                         * (不过对于 plus 操作, 一定是要有返回值的, 不会到达这里)
                         * */
                        Address::new(AddressValue::new_invalid())
                    },
                    _ => {
                        match return_data.typ_attr_ref() {
                            TypeAttrubute::Move => {
                                match &return_data.attr {
                                    FunctionReturnDataAttr::Create => {
                                        /*
                                         * 一定是创建: FunctionReturnDataAttr::Create
                                         * */
                                    },
                                    _ => {
                                        panic!("should not happend: FunctionReturnDataAttr not Create")
                                    }
                                }
                                /*
                                 * 根据类型, 判断是在哪里分配地址
                                 *  返回值地址中的 scope 需要分配为1,
                                 *  因为返回值需要绑定到前一个作用域中
                                 * */
                                scope = Some(1);
                                return_is_alloc = true;
                                let a = self.scope_context.alloc_address(
                                    return_data.typ.to_address_type(), 1);
                                // println!("xxx: {:?}", a);
                                a
                            },
                            _ => {
                                /*
                                 * to_#type 方法一定返回的是一个 Move, 所以这里不会到达
                                 * */
                                panic!("should not happend: TypeAttrubute not Move")
                            }
                        }
                    }
                };
                self.cb_enter_scope();
                /*
                if let Some(context) = param_ref {
                    self.cb.push_param_ref(context);
                }
                */
                if let Some(context) = ref_param_addr {
                    self.cb.add_ref_param_addr(context);
                }
                if let Some(context) = param_move {
                    let (typ, typ_attr, src_addr, index, value_context)
                        = context;
                    self.process_param(
                        &typ, &typ_attr, src_addr, index, value_context);
                }
                let call_context = CallFunctionContext {
                    package_str: input_package_str,
                    func: &func,
                    param_addrs: Some(param_addrs),
                    call_param_len: 1,
                    return_data: CallFunctionReturnData::new_with_all(
                        return_addr.addr_clone(), return_is_alloc)
                };
                self.cb.call_function(call_context);
                self.cb_leave_scope();
                /*
                 * 因为地址被修改, 所以返回修改后的地址 (调用 to_#type 后的 return 地址)
                 *  作用域结束之后, 如果之前修改过scope, 需要减掉
                 * */
                match scope {
                    Some(n) => {
                        return Ok((expect_typ.clone()
                                /*
                                 * to_#type 返回的一定是 Move
                                 * */
                                , TypeAttrubute::Move
                                , return_addr.addr().addr_with_scope_minus(n)));
                    },
                    None => {
                        return Ok((expect_typ.clone()
                                , TypeAttrubute::Move
                                , return_addr.addr()));
                    }
                }
            }
        }
        /*
         * 返回输入的地址
         * */
        Ok((input_typ, input_typ_attr, input_addr.addr()))
    }
}

