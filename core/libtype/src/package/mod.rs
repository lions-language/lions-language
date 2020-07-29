#[derive(Debug, Clone)]
pub enum PackageStr {
    Itself,
    Third(String),
    Empty
}
