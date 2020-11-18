use libcommon::ptr::RefPtr;
use crate::config::{PackageConfig, PackageConfigItem};
use std::path::Path;

struct Control<P: AsRef<Path>> {
    config: PackageConfig<P>
}

impl<P: AsRef<Path>> Control<P> {
    pub fn execute(&mut self) {
        let mut obj = RefPtr::from_ref(self);
        let control = obj.as_mut::<Control<P>>();
        for (name, item) in self.config.into_iter() {
            if item.is_compile {
                control.process_compile(name, item);
            } else {
            }
        }
    }

    fn process_compile(&mut self, name: &str, item: &PackageConfigItem<P>) {
    }

    pub fn new(config: PackageConfig<P>) -> Self {
        Self {
            config: config
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    // #[ignore]
    fn control_test() {
    }
}

