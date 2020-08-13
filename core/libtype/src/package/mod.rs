#[derive(Debug, Clone)]
pub enum PackageStr {
    Itself,
    Third(String),
    Empty
}

impl Default for PackageStr {
    fn default() -> Self {
        PackageStr::Empty
    }
}
