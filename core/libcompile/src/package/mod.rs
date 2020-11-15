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

#[derive(Debug, Clone)]
pub struct PackageContext {
    package: RefPtr
}

impl PackageContext {
    pub fn package_ref<P: AsRef<Path>>(&self) -> &Package<P> {
        self.package.as_ref::<Package<P>>()
    }

    pub fn package_mut<P: AsRef<Path>>(&mut self) -> &mut Package<P> {
        self.package.as_mut::<Package<P>>()
    }

    pub fn new<P: AsRef<Path>>(package: &Package<P>) -> Self {
        Self {
            package: RefPtr::from_ref(package)
        }
    }
}

