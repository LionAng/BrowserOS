#[allow(clippy::all, unused_imports)]
#[path = "generated/mod.rs"]
mod generated;

pub mod models {
    pub use super::generated::*;

    // Local operator revoke response. api/http imports wire models from here.
    pub mod grants;
    pub use self::grants::*;
}

pub use models::*;
