use libtype::{
    TypeAttrubute, TypeValue
    , Type};
use libtype::function::{FindFunctionContext, FindFunctionResult
    , FunctionParamData
    , FunctionParamLengthenAttr
    , CallFunctionParamAddr, Function, splice::FunctionSplice
    , FunctionReturnDataAttr, FunctionParamDataItem
    , FunctionReturnRefParam
    , CallFunctionReturnData};
use libtype::instruction::{PushParamRef};
use libtype::{AddressValue
    , AddressType};
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{CallFuncScopeContext
    , CallFunctionContext as GrammarCallFunctionContext};
use libresult::*;
use libcommon::ptr::RefPtr;
use crate::compile::{Compile, Compiler
    , CallFunctionContext, value_buffer::ValueBufferItem
    , value_buffer::ValueBufferItemContext
    , AddressValueExpand};
use crate::compile::scope::{ScopeFuncCall};
use crate::address::Address;
use std::collections::VecDeque;

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
            if it != et {
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
                let mut param_ref = None;
                let mut param_move = None;
                let param_addrs = vec![CallFunctionParamAddr::Fixed(
                    input_addr.addr_ref().clone_with_scope_plus(1))];
                if input_typ_attr.is_move_as_param() {
                    param_move = Some((input_typ.clone(), input_typ_attr.clone()
                            , input_addr.addr_clone()
                            , 0
                            , input_value_context));
                } else if input_typ_attr.is_ref_as_param() {
                    param_ref = Some(PushParamRef::new_with_all(
                        input_addr.addr_ref().clone_with_scope_plus(1)));
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
                self.cb.enter_scope();
                if let Some(context) = param_ref {
                    self.cb.push_param_ref(context);
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
                self.cb.leave_scope();
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

    pub fn handle_call_function_prepare(&mut self, call_scope_context: CallFuncScopeContext
        , name: TokenValue, call_context: &mut GrammarCallFunctionContext) -> DescResult {
        self.scope_context.enter_func_call();
        /*
         * 1. 查找函数声明
         * */
        let name_data = name.token_data().expect("should not happend");
        let func_str = extract_token_data!(name_data, Id);
        let find_func_context = FindFunctionContext {
            typ: call_scope_context.typ_ref().as_ref(),
            package_typ: call_scope_context.package_type_ref().as_ref(),
            func_str: &func_str,
            module_str: self.module_stack.current().name_ref()
        };
        call_context.set_desc_ctx(call_scope_context.desc_ctx_clone());
        let (exists, handle) = self.function_control.is_exists(&find_func_context);
        if exists {
            let h = Some(handle);
            let func_res = self.function_control.find_function(&find_func_context, &h);
            let func_ptr = match func_res {
                FindFunctionResult::Success(r) => {
                    RefPtr::from_ref(r.func)
                },
                FindFunctionResult::Panic(s) => {
                    return DescResult::Error(s);
                },
                _ => {
                    panic!("should not happend");
                }
            };
            call_context.set_func_ptr(func_ptr);
            call_context.set_package_str(call_scope_context.package_str());
        } else {
            let (package_type, package_str, _, typ) = call_scope_context.fields_move();
            call_context.set_typ(typ);
            call_context.set_func_name(func_str);
            call_context.set_package_str(package_str);
            call_context.set_package_typ(package_type);
            /*
            return DescResult::Error(
                format!("the {} function is not found", func_str));
            */
        }
        DescResult::Success
    }

    pub fn handle_call_function_param_before_expr(&mut self, index: usize
        , call_context: &mut GrammarCallFunctionContext) {
        let func_ptr = call_context.func_ptr_clone();
        if func_ptr.is_null() {
            return;
        }
        /*
         * 在当前函数被调用的时候, 只有内置函数才能找到函数的声明
         * 因为内置函数只检测函数名, 而不检测函数参数
         * */
        let func = func_ptr.as_ref::<Function>();
        let func_statement = func.func_statement_ref();
        match func_statement.func_param_ref() {
            Some(fp) => {
                /*
                 * 存在参数
                 * */
                match fp.data_ref() {
                    FunctionParamData::Single(item) => {
                        let item_typ = item.typ_ref().clone();
                        let is_auto_call_totype = *item.is_auto_call_totype_ref();
                        self.scope_context.set_current_func_call(ScopeFuncCall::new_with_all(
                                is_auto_call_totype, item_typ));
                        // println!("{:?}", &self.compile_context);
                        /*
                         * 只有一个参数, 不管 index 是什么, 都以 该参数信息计算
                         * */
                    },
                    FunctionParamData::Multi(items) => {
                        let param_len = func_statement.get_func_param_len();
                        /*
                         * 如果 index > param_len => 说明最后一个是变长参数
                         * 那么当 index < param_len 的时候, 按照 items[index] 进行计算
                         * 否则, 按照 items 的最后一个元素进行计算
                         * */
                    }
                }
            },
            None => {
            }
        }
    }

    pub fn handle_call_function_param_after_expr(&mut self, index: usize
        , call_context: &mut GrammarCallFunctionContext) {
        let func_ptr = call_context.func_ptr_clone();
        if !func_ptr.is_null() {
            /*
             * 已经找到了函数名, 那么不需要解析类型
             * */
            return;
        }
        let value = self.scope_context.top_n_with_panic_from_value_buffer(1);
        call_context.push_param_typ(value.typ_clone(), value.typ_attr_clone());
    }

    pub fn handle_call_function_get_top_addr(&mut self
        , item: &FunctionParamDataItem)
         -> Result<(Type, TypeAttrubute, AddressValue, ValueBufferItemContext), DescResult> {
        let value = self.scope_context.take_top_from_value_buffer();
        let value_context = value.context_clone();
        // let value_addr = value.addr_ref().addr_clone();
        let value_typ_attr = value.typ_attr_clone();
        match self.binary_type_match(
            value, item.typ_ref()
            , *item.is_auto_call_totype_ref()) {
            Ok(v) => {
                let ta = if value_typ_attr.is_ref() {
                    value_typ_attr
                } else {
                    v.1
                };
                Ok((v.0, ta, v.2, value_context))
            },
            Err(e) => {
                Err(e)
            }
        }
        // Ok(addr_value.clone_with_scope_plus(1))
        /*
        Ok(self.process_param(
            &typ, &typ_attr, addr_value, 0, value_context))
        */
    }

    pub fn handle_call_function(&mut self
        , param_len: usize
        , call_context: GrammarCallFunctionContext) -> DescResult {
        /*
         * 1. 查找函数声明
         * */
        let mut return_is_alloc = false;
        let mut func_ptr = call_context.func_ptr_clone();
        if func_ptr.is_null() {
            /*
             * prepare 阶没有找到函数声明 => 查找
             * */
            let mut param_typs = call_context.param_typs_clone();
            let mut func_param_data = None;
            let param_typs_len = param_typs.len();
            if param_typs_len == 1 {
                let (typ, typ_attr) = param_typs.remove(0);
                func_param_data = Some(FunctionParamData::Single(
                    FunctionParamDataItem::new(typ, typ_attr)));
            } else if param_typs_len > 1 {
                let mut items = Vec::new();
                while !param_typs.is_empty() {
                    let (typ, typ_attr) = param_typs.remove(0);
                    items.push(FunctionParamDataItem::new(typ, typ_attr));
                }
                func_param_data = Some(FunctionParamData::Multi(items));
            }
            let func_str = FunctionSplice::get_function_without_return_string_by_type(
                call_context.func_name_ref().as_ref().expect("should not happend").as_ref()
                , &func_param_data.as_ref(), &call_context.typ_ref().as_ref());
            let find_func_context = FindFunctionContext {
                typ: call_context.typ_ref().as_ref(),
                package_typ: call_context.package_typ_ref().as_ref(),
                func_str: &func_str,
                module_str: self.module_stack.current().name_ref()
            };
            let (exists, handle) = self.function_control.is_exists(&find_func_context);
            if exists {
                let h = Some(handle);
                let func_res = self.function_control.find_function(&find_func_context, &h);
                func_ptr = match func_res {
                    FindFunctionResult::Success(r) => {
                        RefPtr::from_ref(r.func)
                    },
                    FindFunctionResult::Panic(s) => {
                        return DescResult::Error(s);
                    },
                    _ => {
                        panic!("should not happend");
                    }
                };
            } else {
                return DescResult::Error(
                    format!("the {} function is not found", func_str));
            }
        }
        let func = func_ptr.as_ref::<Function>();
        let func_statement = func.func_statement_ref();
        let mut move_param_contexts = Vec::new();
        let mut param_refs = VecDeque::new();
        match func_statement.func_param_ref() {
            Some(fp) => {
                /*
                 * 存在参数
                 * */
                match fp.data_ref() {
                    FunctionParamData::Single(item) => {
                        match item.lengthen_attr_ref() {
                            FunctionParamLengthenAttr::Lengthen => {
                                for _ in 0..param_len {
                                    let (typ, typ_attr, addr_value, value_context)
                                        = match self.handle_call_function_get_top_addr(item) {
                                        Ok(v) => v,
                                        Err(e) => return e
                                    };
                                    if item.is_check_func_call_param_typ_attr_clone() {
                                        /*
                                         * TODO
                                         *  临时方案, 这里是对 println 的特殊处理
                                         * */
                                        if item.typ_attr_ref() != &typ_attr {
                                            return DescResult::Error(
                                                format!("expect typ attr: {:?}, but found {:?}"
                                                    , item.typ_attr_ref(), &typ_attr));
                                        }
                                        if typ_attr.is_move() {
                                            move_param_contexts.push((typ, typ_attr
                                            , addr_value, value_context));
                                        } else if typ_attr.is_ref() {
                                            param_refs.push_front(PushParamRef::new_with_all(
                                                addr_value.clone_with_scope_plus(1)));
                                        } else {
                                            unimplemented!();
                                        }
                                    } else {
                                        param_refs.push_front(PushParamRef::new_with_all(
                                            addr_value.clone_with_scope_plus(1)));
                                    }
                                }
                            },
                            FunctionParamLengthenAttr::Fixed => {
                                if param_len == 1 {
                                    let (typ, typ_attr, addr_value, value_context)
                                        = match self.handle_call_function_get_top_addr(item) {
                                        Ok(v) => v,
                                        Err(e) => return e
                                    };
                                    if item.typ_attr_ref().is_move() {
                                        move_param_contexts.push((typ, typ_attr
                                        , addr_value, value_context));
                                    } else if item.typ_attr_ref().is_ref() {
                                        param_refs.push_front(PushParamRef::new_with_all(
                                            addr_value.clone_with_scope_plus(1)));
                                    } else {
                                        unimplemented!();
                                    }
                                } else {
                                    /*
                                     * 希望是1个固定的参数, 但是参数个数不等于1
                                     * */
                                    return DescResult::Error(
                                        format!("expect 1 param, but got {} param", param_len));
                                }
                            }
                        }
                    },
                    FunctionParamData::Multi(items) => {
                        let statement_param_len = items.len();
                        /*
                         * 检测:
                         *  查看最后一个参数类型是不是可变的
                         * */
                        match items.last().unwrap().lengthen_attr_ref() {
                            FunctionParamLengthenAttr::Lengthen => {
                                if param_len < statement_param_len - 1 {
                                    /*
                                     * 最后一个参数是变长参数, 那么允许不填
                                     * 但是最后一个参数之前的参数必须给定
                                     * */
                                    return DescResult::Error(
                                    format!("expect {} param, but got {}"
                                        , statement_param_len, param_len));
                                }
                                /*
                                 * 参数正确的情况下:
                                 * 1. 绑定前面固定参数
                                 * 2. 绑定变长参数
                                 * NOTE:
                                 *  参数写入到 value_buffer 是栈的顺序,
                                 *  所以需要注意取参数应该用相反的顺序
                                 * => 先绑定变长参数
                                 * */
                                let (fixed_param_len, lengthen_param_len) =
                                    if param_len == statement_param_len - 1 {
                                        (param_len, 0)
                                    } else {
                                        (statement_param_len
                                            , param_len - statement_param_len + 1)
                                    };
                                /*
                                 * 绑定变长参数
                                 * */
                                if lengthen_param_len > 0 {
                                    let lengthen_param_start = fixed_param_len - 1;
                                    for i in 0..lengthen_param_len {
                                        let item = items.get(lengthen_param_start+i).unwrap();
                                        let (typ, typ_attr, addr_value, value_context) = 
                                            match self.handle_call_function_get_top_addr(item) {
                                            Ok(v) => v,
                                            Err(e) => return e
                                        };
                                        if item.typ_attr_ref().is_move() {
                                            move_param_contexts.push((typ, typ_attr
                                            , addr_value, value_context));
                                        } else if item.typ_attr_ref().is_ref() {
                                            param_refs.push_front(PushParamRef::new_with_all(
                                                addr_value.clone_with_scope_plus(1)));
                                        } else {
                                            unimplemented!();
                                        }
                                    }
                                }
                                /*
                                 * 绑定固定参数
                                 * */
                                for i in 0..fixed_param_len {
                                    let item = items.get(i).unwrap();
                                    let (typ, typ_attr, addr_value, value_context)
                                        = match self.handle_call_function_get_top_addr(item) {
                                        Ok(v) => v,
                                        Err(e) => return e
                                    };
                                    if item.typ_attr_ref().is_move() {
                                        move_param_contexts.push((typ, typ_attr
                                        , addr_value, value_context));
                                    } else if item.typ_attr_ref().is_ref() {
                                        param_refs.push_front(PushParamRef::new_with_all(
                                            addr_value.clone_with_scope_plus(1)));
                                    } else {
                                        unimplemented!();
                                    }
                                }
                            },
                            FunctionParamLengthenAttr::Fixed => {
                                if statement_param_len != param_len {
                                    /*
                                     * 最后一个参数不是变长的,
                                     * 但是给定的参数和函数声明的参数长度不一致, 则报错
                                     * */
                                    return DescResult::Error(
                                    format!("expect {} param, but got {}"
                                        , statement_param_len, param_len));
                                }
                                for i in 0..param_len {
                                    let item = items.get(i).unwrap();
                                    let (typ, typ_attr, addr_value, value_context)
                                        = match self.handle_call_function_get_top_addr(item) {
                                        Ok(v) => v,
                                        Err(e) => return e
                                    };
                                    // println!("{:?}", addr_value);
                                    if item.typ_attr_ref().is_move_as_param() {
                                        move_param_contexts.push((typ, typ_attr
                                        , addr_value, value_context));
                                    } else if item.typ_attr_ref().is_ref_as_param() {
                                        param_refs.push_front(PushParamRef::new_with_all(
                                            addr_value.clone_with_scope_plus(1)));
                                    } else {
                                        unimplemented!();
                                    }
                                }
                            }
                        }
                    }
                }
            },
            None => {
            }
        }
        let return_data = &func_statement.func_return.data;
        let mut scope: Option<usize> = None;
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
                    TypeAttrubute::Move
                    | TypeAttrubute::CreateRef => {
                        /*
                         * 根据类型, 判断是在哪里分配地址
                         *  返回值地址中的 scope 需要分配为1,
                         *  因为返回值需要绑定到前一个作用域中
                         *   因为该绑定在函数调用中进行, 那时候虚拟机并没有退出函数调用作用域
                         *   所以, 需要将作用域加1
                         * */
                        scope = Some(1);
                        return_is_alloc = true;
                        let a = self.scope_context.alloc_address(
                            return_data.typ_ref().to_address_type(), 1);
                        a
                    },
                    TypeAttrubute::Ref
                    | TypeAttrubute::MutRef => {
                        match return_data.attr_ref() {
                            FunctionReturnDataAttr::RefParam(ref_param) => {
                                match ref_param {
                                    FunctionReturnRefParam::Addr(addr_value) => {
                                        // let index = addr_value.addr_ref().index_clone();
                                        let index = if let AddressType::ParamRef(idx)
                                            = addr_value.typ_ref() {
                                            idx.clone() as u64
                                        } else {
                                            panic!("should not happend");
                                        };
                                        // println!("{}", index);
                                        let lengthen_offset =
                                            addr_value.addr_ref().lengthen_offset_clone();
                                        let param_ref = &param_refs[index as usize+lengthen_offset];
                                        let mut ak = param_ref.addr_ref().addr_clone();
                                        *ak.index_mut() += addr_value.addr_ref().index_clone();
                                        /*
                                         * -1 的目的:
                                         *  因为 param_ref 的值是上面分析 参数引用时得到的
                                         *   而, 计算参数引用的时候, 为了在函数调用的时候正确计算
                                         *   所以, 在scope上加了1, 但是这里需要将其还原
                                         *  返回值为引用的情况下, 写入到 value_buffer
                                         *  中的应该就是未进入函数调用作用域之前的作用域
                                         * */
                                        *ak.scope_mut() -= 1;
                                        let addr = AddressValue::new(
                                            param_ref.addr_ref().typ_clone()
                                            , ak);
                                        Address::new(addr.clone())
                                    },
                                    FunctionReturnRefParam::Index(_) => {
                                        unimplemented!();
                                    }
                                }
                            },
                            _ => {
                                panic!("should not happend");
                            }
                        }
                    },
                    _ => {
                        unimplemented!("{:?}", return_data.typ_attr_ref());
                    }
                }
            }
        };
        self.cb.enter_scope();
        while !param_refs.is_empty() {
            let context = param_refs.remove(0).expect("should not happend");
            self.cb.push_param_ref(context);
        }
        let mut move_index = 0;
        while !move_param_contexts.is_empty() {
            let (typ, typ_attr, dst_addr, value_context) =
                move_param_contexts.remove(0);
            /*
             * NOTE
             * 因为 process_param 中会让虚拟机执行移动操作
             * 所以必须要在虚拟机进入作用域之后执行
             * 如果 process_param 中存在移动, 则返回新的地址
             *  如果不存在移动, 则返回输入的地址
             * */
            self.process_param(
                &typ, &typ_attr, dst_addr, move_index, value_context);
            move_index += 1;
        }
        let desc_ctx = call_context.desc_ctx_clone();
        let cc = CallFunctionContext {
            package_str: call_context.package_str(),
            func: &func,
            param_addrs: None,
            call_param_len: param_len,
            return_data: CallFunctionReturnData::new_with_all(
                return_addr.addr_clone(), return_is_alloc)
        };
        self.cb.call_function(cc);
        self.cb.leave_scope();
        match scope {
            Some(n) => {
                return_addr.addr_mut().addr_mut_with_scope_minus(n);
            },
            None => {
            }
        }
        /*
         * 获取返回类型, 将其写入到队列中
         * */
        if !return_addr.is_invalid() {
            let ta = if desc_ctx.typ_attr_ref().is_ref() {
                desc_ctx.typ_attr()
            } else {
                return_data.typ_attr_ref().clone()
            };
            self.scope_context.push_with_addr_typattr_to_value_buffer(
                return_data.typ.clone()
                , return_addr, ta);
        }
        // self.compile_context.reset();
        self.scope_context.leave_func_call();
        DescResult::Success
    }
}

