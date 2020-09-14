use libcommon::ptr::RefPtr;
use super::{FunctionStatement, FunctionParam, FunctionReturn
        , FunctionParamData, FunctionReturnData};
use crate::function::splice::FunctionSplice;
use crate::{Type};

impl FunctionStatement {
    pub fn statement_full_str(&self) -> &str {
        match &self.statement_str {
            Some(s) => {
                s
            },
            None => {
                let func_param_data = match &self.func_param {
                    Some(fp) => {
                        Some(fp.data_ref())
                    },
                    None => {
                        None
                    }
                };
                let statement_str = FunctionSplice::get_function_without_return_string_by_type(
                    &self.func_name, &func_param_data, &self.typ.as_ref());
                /*
                let statement_str = FunctionStatement::calc_function_statement_string(
                    &self.func_name, &self.func_param, &self.func_return, &self.typ);
                */
                let mut p = RefPtr::from_ref(self);
                // println!("ptr: {:?}", p);
                p.as_mut::<FunctionStatement>().statement_str = Some(statement_str);
                match &self.statement_str {
                    Some(s) => {
                        s
                    },
                    None => {
                        panic!("should not happend");
                    }
                }
            }
        }
    }
}

impl FunctionStatement {
    fn calc_function_statement_string(func_name: &str, func_param: &Option<FunctionParam>
            , func_return: &FunctionReturn, typ: &Option<Type>) -> String {
        /*
         * 函数名(参数类型列表)->(返回值类型列表)
         * */
        let mut s = String::new();
        /*
         * 存在类型名
         * */
        match typ {
            Some(t) => {
                s.push_str(t.to_attrubute_str());
                s.push_str(&t.to_str());
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
                        s.push_str(p.typ.to_attrubute_str());
                        s.push_str(&p.typ.to_str());
                    },
                    FunctionParamData::Multi(ps) => {
                        for (i, p) in ps.iter().enumerate() {
                            if i > 0 {
                                s.push(',');
                            }
                            s.push_str(p.typ.to_attrubute_str());
                            s.push_str(&p.typ.to_str());
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
        s.push_str("->");
        s.push_str(func_return.data.typ.to_attrubute_str());
        s.push_str(&func_return.data.typ.to_str());
        s
    }
}

impl FunctionStatement {
    pub fn new(func_name: String, func_param: Option<FunctionParam>
            , func_return: FunctionReturn, typ: Option<Type>) -> Self {
        Self {
            func_name: func_name,
            func_param: func_param,
            func_return: func_return,
            typ: typ,
            statement_str: None
        }
    }
}
