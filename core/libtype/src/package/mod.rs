use libcommon::ptr::{RefPtr};

#[derive(Debug, Clone)]
pub enum PackageStr {
    Itself,
    Third(PackageBufferPtr),
    Empty
}

impl Default for PackageStr {
    fn default() -> Self {
        PackageStr::Empty
    }
}

#[derive(Debug, Clone)]
pub struct PackageBufferPtr {
    pub function_control: RefPtr,
    pub module_mapping: RefPtr
}

