//! Pages — each top-level tab in the Atrium shell.

pub mod docs;
pub mod home;
pub mod purge;
pub mod settings;
pub mod tidy;

/// Top-level navigation pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Home,
    Tidy,
    Purge,
    Docs,
    Settings,
}

impl Page {
    pub const ALL: [Page; 5] = [
        Page::Home,
        Page::Tidy,
        Page::Purge,
        Page::Docs,
        Page::Settings,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Page::Home => "Home",
            Page::Tidy => "Tidy",
            Page::Purge => "Purge",
            Page::Docs => "Docs",
            Page::Settings => "Settings",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Page::Home => "⌂",
            Page::Tidy => "◎",
            Page::Purge => "⚠",
            Page::Docs => "?",
            Page::Settings => "⚙",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Page::Home => "Dashboard and environment overview",
            Page::Tidy => "Everyday cleanup — duplicates, old files, large files",
            Page::Purge => "Antiforensic destruction — use sparingly",
            Page::Docs => "How to use Atrium safely",
            Page::Settings => "Theme, protected paths, defaults",
        }
    }
}
