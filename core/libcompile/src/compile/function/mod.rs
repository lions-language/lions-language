use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{FunctionDefineParamContext
    , FunctionDefineParamMutContext
    , FunctionDefineReturnContext
    , FunctionDefineContext
    , TypeToken};
use libtype::function::{AddFunctionContext
    , FunctionParamDataItem
    , FunctionReturnData, FunctionReturn
    , FunctionStatement};
use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, Type
    , AddressKey, AddressValue
    , AddressType};
use libtype::instruction::{JumpType, Jump};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext
    , TypeTokenExpand};
use crate::compile::scope::vars::Variant;
use crate::compile::scope::ScopeType;
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_function_named_stmt(&mut self, value: TokenValue) {
        self.scope_context.enter(ScopeType::Function);
        let s = match value.token_data.expect("should not happend") {
            TokenData::Id(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        };
        let statement_ptr = self.cb.function_named_stmt(FunctionNamedStmtContext{
            name: s
        });
    }

    pub fn handle_function_define_param(&mut self, context: FunctionDefineParamContext
        , mut_context: &mut FunctionDefineParamMutContext) {
        let (name_token, type_token, typ_attr, lengthen_attr, param_no)
            = context.fields_move();
        let name = extract_token_data!(
           name_token.token_data().expect("should not happend")
           , Id);
        let typ = self.to_type(type_token);
        /*
         * 为参数分配一个地址
         *  只是分配一个地址, 不做其他事情 (就是增加地址分配器的索引,
         *  函数体中的起始地址是从参数个数开始的)
         * NOTE
         *  只有移动的参数才需要分配
         * */
        let addr = if typ_attr.is_move() {
            self.scope_context.alloc_address(
                typ.to_address_type(), 0)
        } else if typ_attr.is_ref() {
            /*
            let a = Address::new(AddressValue::new(
                    AddressType::ParamRef(mut_context.ref_param_no_clone())
                    , AddressKey::default()));
            *mut_context.ref_param_no_mut() += 1;
            a
            */
            self.scope_context.alloc_address(
                AddressType::AddrRef, 0)
        } else {
            unimplemented!();
        };
        /*
         * 将函数参数地址索引, 写入到当前作用域中
         * */
        self.scope_context.current_mut_unchecked()
            .add_func_param_addr_index(addr.addr_ref().addr_index_clone()
                , typ_attr.clone());
        /*
         * 添加到变量列表中
         * 其中:
         *  地址是参数的序号
         * */
        self.scope_context.add_variant(name
            , Variant::new(
                /*
                Address::new(AddressValue::new(typ.to_address_type()
                        , AddressKey::new(param_no as u64)))
                */
                addr
                , typ.clone(), typ_attr.clone()));
        /*
         * 填充函数声明
         * */
        let func_param_item = FunctionParamDataItem::new_with_lengthen(
            typ, typ_attr, lengthen_attr);
        self.cb.function_push_param_to_statement(func_param_item);
    }

    pub fn handle_function_define_return(&mut self, context: FunctionDefineReturnContext) {
        let (typ_attr, _, type_token) = context.fields_move();
        let func_return_data = FunctionReturnData::new(
            self.to_type(type_token), typ_attr);
        let func_return = FunctionReturn::new(func_return_data);
        self.scope_context.set_current_func_return(func_return.clone());
        self.cb.function_set_return_to_statement(func_return);
    }

    pub fn handle_function_define_start(&mut self) {
        self.cb.function_define_start();
    }

    pub fn handle_function_define_end(&mut self
        , define_context: &FunctionDefineContext) {
        self.fill_return_jumps();
        // println!("{:?}", self.scope_context.get_current_func_return_ref());
        let func = self.cb.function_define_end();
        // println!("{:?}", func.func_statement_ref().statement_full_str());
        let package_typ = PackageType::new(PackageTypeValue::Crate);
        let context = AddFunctionContext{
            func_name: func.func_statement_ref().func_name_clone(),
            typ: None,
            package_typ: Some(&package_typ),
            module_str: self.module_stack.current().to_str().to_string(),
            // func_str: func.func_statement_ref().func_name.clone()
            func_str: func.func_statement_ref().statement_full_str().to_string(),
            is_overload: if define_context.has_lengthen_param_clone() {false} else {true}
        };
        // println!("{:?}", context);
        // println!("{:?}", func);
        self.function_control.add_function(context, None, func);
        self.scope_context.leave();
    }

    fn fill_return_jumps(&mut self) {
        let return_jumps = self.scope_context.current_unchecked().get_all_return_jumps_ref();
        match return_jumps {
            Some(rs) => {
                let current_index = self.cb.current_index();
                for ins in rs {
                    /*
                     * 计算函数定义结束时的索引和 jump 指令之间的偏移
                     * */
                    let offset = current_index - *ins;
                    /*
                     * offset 只是两条指令之间的距离, 但是因为需要跳过它们,
                     * 所以需要对 offset 加1, 最终的结果才是 要跳转后的位置
                     * */
                    let jump_index = offset + 1;
                    // println!("jump index: {}", jump_index);
                    /*
                     * 更新 jump 指令中的值
                     * */
                    self.cb.set_jump(*ins, Jump::new_with_all(
                            JumpType::Backward, jump_index));
                }
            },
            None => {
            }
        }
    }
}
