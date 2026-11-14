//! Report rendering.
//!
//! * [`pretty`] writes the terminal report, with colour only when asked.
//! * [`html`] writes one self-contained dashboard with no external assets.

pub mod html;
pub mod pretty;

pub use html::{render_report, render_web};
pub use pretty::render_pretty;
