#[derive(Debug,Clone)]
pub enum RouteCmdKind {
    Add,
    Set,
    Delete
}
#[derive(Debug,Clone)]
pub struct RouteCmd {
    pub kind: RouteCmdKind,
    pub cmd: String,
}
impl RouteCmd {
    pub fn add(cmd: String) -> Self {
        Self {
            kind: RouteCmdKind::Add,
            cmd,
        }
    }

    pub fn set(cmd: String) -> Self {
        Self {
            kind: RouteCmdKind::Set,
            cmd,
        }
    }

    pub fn delete(cmd: String) -> Self {
        Self {
            kind: RouteCmdKind::Delete,
            cmd,
        }
    }
}