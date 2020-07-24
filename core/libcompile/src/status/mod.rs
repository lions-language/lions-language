use libmacro::FieldGet;
use libcommon::ptr::RefPtr;

pub enum CompileStatusType {
    /*
     * 一个引用的指针 (可能是 DefineFunction 实体对象的引用)
     * */
    FunctionDefine(RefPtr),
    Call
}

#[derive(FieldGet)]
pub struct CompileStatus {
    status: CompileStatusType
}

impl CompileStatus {
    pub fn new(status: CompileStatusType) -> Self {
        Self {
            status: status
        }
    }
}

impl Default for CompileStatus {
    fn default() -> Self {
        Self {
            status: CompileStatusType::Call
        }
    }
}
