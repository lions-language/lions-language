use libresult::*;
use libgrammar::token::TokenValue;
use libtype::function::{FunctionParamData, FunctionParamDataItem
        , splice::FunctionSplice, FindFunctionContext
        , FindFunctionResult};
use crate::compile::{Compile, Compiler, CallFunctionContext};

impl<F: Compile> Compiler<F> {
    pub fn operator_plus(&mut self, _value: TokenValue) -> DescResult {
        use libtype::function::consts;
        /*
         * 取出前两个token, 查找第一个函数的 plus 方法
         * */
        let right = self.value_buffer.take_top();
        let left = self.value_buffer.take_top();
        /*
         * 构建方法所属类型 => left 类型
         * */
        let typ = left;
        /*
         * 构建 函数参数
         * + 号运算一定只有一个参数
         * */
        let param = FunctionParamData::Single(FunctionParamDataItem::new(right.typ));
        let statement_str = FunctionSplice::get_function_without_return_string_by_type(
            consts::OPERATOR_FUNCTION_NAME, &Some(&param), &Some(&typ.typ));
        /*
         * 查找方法声明
         * */
        match self.function_control.find_function(&FindFunctionContext{
            typ: &typ.typ,
            func_str: &statement_str,
            module_str: self.module_stack.current().to_str()
        }) {
            FindFunctionResult::Success(r) => {
                /*
                 * 获取返回类型, 如果存在返回类型, 将其写入到队列中
                 * */
                self.cb.call_function(CallFunctionContext{
                    func: r.func
                });
                self.value_buffer.push(r.func.func_statement.func_return.data.typ.clone());
            },
            FindFunctionResult::Panic(desc) => {
                return DescResult::Error(desc);
            }
        }
        DescResult::Success
    }
}

