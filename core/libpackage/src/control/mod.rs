use crate::config::PackageConfig;
use std::path::Path;

struct Control<P: AsRef<Path>> {
    config: PackageConfig<P>
}

impl<P: AsRef<Path>> Control<P> {
    pub fn execute(&mut self) {
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

