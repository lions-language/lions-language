use libtype::package::{PackageBuffer};
use libcommon::ptr::RefPtr;
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

#[derive(Debug)]
pub struct PackageControl {
    buffer: HashMap<String, PackageBuffer>
}

impl PackageControl {
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

    pub fn new<P: AsRef<Path>>(package: &Package<P>
        , package_control: &PackageControl) -> Self {
        Self {
            package: RefPtr::from_ref(package),
            package_control: RefPtr::from_ref(package_control)
        }
    }
}

