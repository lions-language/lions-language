use std::path::Path;
use std::collections::HashMap;

#[derive(Debug)]
pub struct PackageConfigItem<P: AsRef<Path>> {
    pub is_compile: bool,
    pub path: P,
    pub lib_path: Option<String>
}

impl<P: AsRef<Path>> PackageConfigItem<P> {
    pub fn new(is_compile: bool, path: P
        , lib_path: Option<String>) -> Self {
        Self {
            is_compile: is_compile,
            path: path,
            lib_path: lib_path
        }
    }
}

pub struct PackageConfig<P: AsRef<Path>> {
    items: HashMap<String, PackageConfigItem<P>>
}

impl<'a, P: AsRef<Path>> IntoIterator for &'a PackageConfig<P> {
    type Item = (&'a String, &'a PackageConfigItem<P>);
    type IntoIter = std::collections::hash_map::Iter<'a, String, PackageConfigItem<P>>;

    #[inline]
    fn into_iter(self) -> std::collections::hash_map::Iter<'a, String, PackageConfigItem<P>> {
        self.items.iter()
    }
}

impl<P: AsRef<Path>> PackageConfig<P> {
    pub fn new() -> Self {
        Self {
            items: HashMap::new()
        }
    }
}

