use libtypecontrol::function::FunctionControl;
use libcommon::ptr::RefPtr;
use libtype::package::{PackageBufferPtr};
use std::path::Path;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Package<P: AsRef<Path>> {
    mapping: HashMap<String, P>
}

impl<P: AsRef<Path>> Package<P> {
    pub fn new() -> Self {
        Self {
            mapping: HashMap::new()
        }
    }
}

pub struct PackageBuffer {
    pub function_control: FunctionControl
}

impl From<&PackageBuffer> for PackageBufferPtr {
    fn from(v: &PackageBuffer) -> Self {
        Self {
            function_control: RefPtr::from_ref(&v.function_control)
        }
    }
}

pub struct PackageControl {
    buffer: HashMap<String, PackageBuffer>
}

impl PackageControl {
    pub fn insert(&mut self, name: String, buffer: PackageBuffer) {
        self.buffer.insert(name, buffer);
    }

    pub fn get_ref(&self, name: &str) -> Option<&PackageBuffer> {
        self.buffer.get(name)
    }

    pub fn get_ptr_clone(&self, name: &str) -> Option<PackageBufferPtr> {
        match self.buffer.get(name) {
            Some(b) => {
                Some(b.into())
            },
            None => {
                None
            }
        }
    }

    pub fn new() -> Self {
        Self {
            buffer: HashMap::new()
        }
    }
}

#[derive(Debug)]
pub struct PackageContext {
    /*
     * 存储包的配置信息
     * 主要用于: 如果包没有编译的情况下, 需要根据配置信息进行编译
     * */
    package: RefPtr,
    /*
     * 如果包编译完成, 需要将编译好的结果存储在 control 中
     * */
    package_control: RefPtr
}

impl PackageContext {
    pub fn package_ref<P: AsRef<Path>>(&self) -> &Package<P> {
        self.package.as_ref::<Package<P>>()
    }

    pub fn package_mut<P: AsRef<Path>>(&mut self) -> &mut Package<P> {
        self.package.as_mut::<Package<P>>()
    }

    pub fn package_control_ref(&self) -> &PackageControl {
        self.package_control.as_ref::<PackageControl>()
    }

    pub fn package_control_mut(&mut self) -> &mut PackageControl {
        self.package_control.as_mut::<PackageControl>()
    }

    pub fn new<P: AsRef<Path>>(package: &Package<P>
        , package_control: &PackageControl) -> Self {
        Self {
            package: RefPtr::from_ref(package),
            package_control: RefPtr::from_ref(package_control)
        }
    }
}

