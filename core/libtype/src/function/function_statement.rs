use super::{FunctionStatement, FunctionParam, FunctionReturn
        , FunctionParamData, FunctionReturnData};
use crate::{Type};

impl FunctionStatement {
    pub fn statement_full_str(&self) -> &str {
        &self.statement_str
    }
}

impl FunctionStatement {
    fn calc_function_statement_string(func_name: &str, func_param: &Option<FunctionParam>
            , func_return: &Option<FunctionReturn>, typ: &Option<Type>) -> String {
        /*
         * 函数名(参数类型列表)->(返回值类型列表)
         * */
        let mut s = String::new();
        /*
         * 存在类型名
         * */
        match typ {
            Some(t) => {
                s.push_str(t.to_str());
                s.push(':');
            },
            None => {
            }
        }
        /*
         * 拼接函数名
         * */
        s.push_str(&func_name);
        /*
         * 拼接参数列表
         * */
        s.push('(');
        match func_param {
            Some(param) => {
                match &param.data {
                    FunctionParamData::Single(p) => {
                        s.push_str(p.typ.to_str());
                    },
                    FunctionParamData::Multi(ps) => {
                        for (i, p) in ps.iter().enumerate() {
                            if i > 0 {
                                s.push(',');
                            }
                            s.push_str(p.typ.to_str());
                        }
                    }
                }
            },
            None => {
            }
        }
        s.push(')');
        /*
         * 拼接返回值
         * */
        match func_return {
            Some(ret) => {
                s.push_str("->");
                s.push_str(ret.data.typ.to_str());
            },
            None => {
            }
        }
        s
    }
}

impl FunctionStatement {
    pub fn new(func_name: String, func_param: Option<FunctionParam>
            , func_return: Option<FunctionReturn>, typ: Option<Type>) -> Self {
        let statement_str = FunctionStatement::calc_function_statement_string(
            &func_name, &func_param, &func_return, &typ);
        Self {
            func_name: func_name,
            func_param: func_param,
            func_return: func_return,
            typ: typ,
            statement_str: statement_str
        }
    }
}
