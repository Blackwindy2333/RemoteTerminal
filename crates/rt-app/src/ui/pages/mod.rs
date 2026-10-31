//! One module per top-level view.
//!
//! Every page exposes the same surface:
//! - `State` — everything the page remembers between frames (call it `seed_from_config`
//!   once at start-up);
//! - `poll` — drains background results, called from `App::update`;
//! - `ui` — draws the page into the central panel;
//! - `dialogs` — draws the page's modals above the window chrome.

pub mod dashboard;
pub mod exec;
pub mod files;
pub mod logs;
pub mod screen;
pub mod settings;
