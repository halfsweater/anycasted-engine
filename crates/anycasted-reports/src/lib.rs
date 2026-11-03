//! Report rendering.
//!
//! * [`json`] — the canonical, versioned machine-readable format.
//! * [`text`] — human-readable terminal output used by the CLI.

pub mod json;
pub mod text;

pub use json::{to_json, to_json_pretty, write_json};
pub use text::{TextOptions, banner, render};
