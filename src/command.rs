use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppCommand {
    Sync,
    AddAccount,
    RemoveAccount,
    AuthorizeAccount,
    Compose,
    Search,
    FocusAccounts,
    FocusFolders,
    FocusMessages,
    FocusPreview,
    NextAccount,
    PreviousAccount,
    NextFolder,
    PreviousFolder,
    Quit,
}

#[derive(Clone, Copy, Debug)]
pub struct CommandSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub aliases: &'static [&'static str],
    pub action: AppCommand,
}

#[derive(Clone, Debug)]
pub struct CommandMatch {
    pub action: AppCommand,
    pub name: &'static str,
    pub description: &'static str,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "sync",
        description: "Fetch mail for the selected account and folder",
        aliases: &["refresh", "check-mail"],
        action: AppCommand::Sync,
    },
    CommandSpec {
        name: "add-account",
        description: "Open the in-app account login/setup wizard",
        aliases: &["account", "login", "setup-account"],
        action: AppCommand::AddAccount,
    },
    CommandSpec {
        name: "remove-account",
        description: "Remove the currently selected account",
        aliases: &["delete-account", "rm-account"],
        action: AppCommand::RemoveAccount,
    },
    CommandSpec {
        name: "authorize-account",
        description: "Run OAuth for the selected Gmail or Outlook account",
        aliases: &["oauth", "gmail-oauth", "outlook-oauth", "reauth"],
        action: AppCommand::AuthorizeAccount,
    },
    CommandSpec {
        name: "compose",
        description: "Open the message composer",
        aliases: &["new", "send-mail"],
        action: AppCommand::Compose,
    },
    CommandSpec {
        name: "search",
        description: "Search synced messages by subject, sender, date, preview, or body",
        aliases: &["find", "grep-mail", "/"],
        action: AppCommand::Search,
    },
    CommandSpec {
        name: "focus-accounts",
        description: "Move focus to the accounts pane",
        aliases: &["fa", "accounts"],
        action: AppCommand::FocusAccounts,
    },
    CommandSpec {
        name: "focus-folders",
        description: "Move focus to the folders pane",
        aliases: &["ff", "folders"],
        action: AppCommand::FocusFolders,
    },
    CommandSpec {
        name: "focus-messages",
        description: "Move focus to the messages pane",
        aliases: &["fm", "messages", "threads"],
        action: AppCommand::FocusMessages,
    },
    CommandSpec {
        name: "focus-preview",
        description: "Move focus to the preview pane",
        aliases: &["fp", "preview", "reader"],
        action: AppCommand::FocusPreview,
    },
    CommandSpec {
        name: "next-account",
        description: "Select the next configured account",
        aliases: &["an", "account-next"],
        action: AppCommand::NextAccount,
    },
    CommandSpec {
        name: "prev-account",
        description: "Select the previous configured account",
        aliases: &["ap", "account-prev"],
        action: AppCommand::PreviousAccount,
    },
    CommandSpec {
        name: "next-folder",
        description: "Select the next folder for the current account",
        aliases: &["fn", "folder-next"],
        action: AppCommand::NextFolder,
    },
    CommandSpec {
        name: "prev-folder",
        description: "Select the previous folder for the current account",
        aliases: &["fpv", "folder-prev"],
        action: AppCommand::PreviousFolder,
    },
    CommandSpec {
        name: "quit",
        description: "Exit the client",
        aliases: &["q", "exit"],
        action: AppCommand::Quit,
    },
];

pub fn search_commands(query: &str) -> Vec<CommandMatch> {
    let query = query.trim();
    if query.is_empty() {
        return COMMANDS
            .iter()
            .map(|command| CommandMatch {
                action: command.action,
                name: command.name,
                description: command.description,
            })
            .collect();
    }

    let matcher = SkimMatcherV2::default().ignore_case();
    let mut matches: Vec<(i64, usize, &CommandSpec)> = COMMANDS
        .iter()
        .enumerate()
        .filter_map(|(index, command)| {
            score_command(&matcher, command, query).map(|score| (score, index, command))
        })
        .collect();

    matches.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    matches
        .into_iter()
        .map(|(_, _, command)| CommandMatch {
            action: command.action,
            name: command.name,
            description: command.description,
        })
        .collect()
}

fn score_command(matcher: &SkimMatcherV2, command: &CommandSpec, query: &str) -> Option<i64> {
    let mut best = matcher.fuzzy_match(command.name, query);

    for alias in command.aliases {
        best = best.max(matcher.fuzzy_match(alias, query));
    }

    best.or_else(|| {
        matcher
            .fuzzy_match(command.description, query)
            .map(|score| score / 4)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_is_returned_first() {
        let matches = search_commands("sync");
        assert_eq!(
            matches.first().map(|item| item.action),
            Some(AppCommand::Sync)
        );
    }

    #[test]
    fn alias_match_works() {
        let matches = search_commands("threads");
        assert_eq!(
            matches.first().map(|item| item.action),
            Some(AppCommand::FocusMessages)
        );
    }
}
