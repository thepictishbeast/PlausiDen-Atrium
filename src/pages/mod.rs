//! Pages — each top-level tab in the Atrium shell.

pub mod docs;
pub mod home;
pub mod settings;
pub mod tidy;
pub mod tools;

/// Top-level navigation pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Home,
    Tidy,
    Tools,
    Docs,
    Settings,
}

impl Page {
    pub const ALL: [Page; 5] = [
        Page::Home,
        Page::Tidy,
        Page::Tools,
        Page::Docs,
        Page::Settings,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Page::Home => "Home",
            Page::Tidy => "Tidy",
            Page::Tools => "Tools",
            Page::Docs => "Docs",
            Page::Settings => "Settings",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Page::Home => "⌂",
            Page::Tidy => "◎",
            Page::Tools => "⚙",
            Page::Docs => "?",
            Page::Settings => "◇",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Page::Home => "Dashboard and environment overview",
            Page::Tidy => "Cleanup — duplicates, old files, large files, caches, plan",
            Page::Tools => "Forensic recovery tools, wipe presets, block devices",
            Page::Docs => "How to use Atrium safely",
            Page::Settings => "Theme, protected paths, safety lock",
        }
    }
}
