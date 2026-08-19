use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use p5_core::{default_root, DeliveryMode, MailItem, Mailbox, MailboxError, PeerType};

const PRODUCT: &str = "Postal";
const SITE: &str = "postal.bot";
const COMMAND: &str = "p5";

/// Postal — inter-bot mail by Alakazam Labs.
#[derive(Debug, Parser)]
#[command(
    name = "p5",
    version = env!("CARGO_PKG_VERSION"),
    about = "Postal — inter-bot mail (postal.bot)",
    after_help = "Product: Postal / postal.bot. Command: p5. See also: p5 help types",
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print this CLI's identity (works without ~/.postal)
    Whoami,
    /// Show help, or a topic (`p5 help types`)
    Help {
        /// Help topic
        topic: Option<HelpTopic>,
    },
    /// Local inbox (cover markdown + optional sidecars)
    Inbox {
        #[command(subcommand)]
        action: Option<InboxAction>,
    },
    /// Sender ledger (never deleted)
    Sent {
        #[command(subcommand)]
        action: Option<SentAction>,
    },
    /// Retry queue (still ours to flush)
    Outbox {
        #[command(subcommand)]
        action: Option<OutboxAction>,
    },
}

#[derive(Debug, Subcommand)]
enum InboxAction {
    /// List items (optional folder: active, done, …)
    List { folder: Option<String> },
    /// Print a cover
    Read { id: String },
}

#[derive(Debug, Subcommand)]
enum SentAction {
    /// List the sent ledger
    List,
}

#[derive(Debug, Subcommand)]
enum OutboxAction {
    /// List the retry queue
    List,
}

#[derive(Debug, Clone, ValueEnum)]
enum HelpTopic {
    /// Bot types: session and turn (live/tray are modes)
    Types,
}

fn whoami_text() -> String {
    format!(
        "{PRODUCT} ({SITE})\ncommand: {COMMAND}\nversion: {}\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn help_types_text() -> String {
    let session = PeerType::Session.as_str();
    let turn = PeerType::Turn.as_str();
    let live = DeliveryMode::Live.as_str();
    let tray = DeliveryMode::Tray.as_str();
    format!(
        "\
Bot types (one word on the wire / in p5 config):

  {session}  Lives in a terminal harness. Attach if live; if asleep,
           resume from a saved session file + cwd.

  {turn}     Host-scheduled agent (Grok Bot / Sand). A message is a
           new user turn. No always-on process.

Delivery modes (not types):

  {live}     Short inject (session only).
  {tray}     Durable package + optional knock.
"
    )
}

fn help_text() -> String {
    let mut cmd = Cli::command();
    let mut buf = Vec::new();
    cmd.write_help(&mut buf).expect("help");
    String::from_utf8(buf).expect("utf8")
}

fn mailbox() -> Mailbox {
    Mailbox::new(default_root())
}

fn format_sent_line(item: &MailItem) -> String {
    format!(
        "{}  {:<10}  {:<4}  {:<7}  {}  attempts={}",
        item.id,
        item.status.as_str(),
        item.mode.as_str(),
        item.typ.as_str(),
        item.to,
        item.attempts
    )
}

fn format_inbox_line(item: &MailItem) -> String {
    format!("{}  {}  {}", item.id, item.from, item.to)
}

fn print_lines(lines: impl IntoIterator<Item = String>) {
    for line in lines {
        println!("{line}");
    }
}

fn inbox_cmd(action: Option<InboxAction>) -> Result<(), MailboxError> {
    let mb = mailbox();
    match action {
        None | Some(InboxAction::List { folder: None }) => {
            print_lines(
                mb.list_inbox(None, None)?
                    .into_iter()
                    .map(|i| format_inbox_line(&i)),
            );
            Ok(())
        }
        Some(InboxAction::List {
            folder: Some(folder),
        }) => {
            print_lines(
                mb.list_inbox(None, Some(&folder))?
                    .into_iter()
                    .map(|i| format_inbox_line(&i)),
            );
            Ok(())
        }
        Some(InboxAction::Read { id }) => {
            print!("{}", mb.read_inbox_cover(&id)?);
            Ok(())
        }
    }
}

fn sent_cmd(action: Option<SentAction>) -> Result<(), MailboxError> {
    let items = mailbox().list_sent()?;
    match action {
        None | Some(SentAction::List) => {
            print_lines(items.iter().map(format_sent_line));
            Ok(())
        }
    }
}

fn outbox_cmd(action: Option<OutboxAction>) -> Result<(), MailboxError> {
    let items = mailbox().list_outbox()?;
    match action {
        None | Some(OutboxAction::List) => {
            print_lines(items.iter().map(format_sent_line));
            Ok(())
        }
    }
}

fn run_mailbox(result: Result<(), MailboxError>) {
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(err.exit_code());
    }
}

fn main() {
    match Cli::parse().command {
        Commands::Whoami => print!("{}", whoami_text()),
        Commands::Help { topic: None } => {
            print!("{}", help_text());
        }
        Commands::Help {
            topic: Some(HelpTopic::Types),
        } => print!("{}", help_types_text()),
        Commands::Inbox { action } => run_mailbox(inbox_cmd(action)),
        Commands::Sent { action } => run_mailbox(sent_cmd(action)),
        Commands::Outbox { action } => run_mailbox(outbox_cmd(action)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_is_stub_identity() {
        let text = whoami_text();
        assert!(text.contains(PRODUCT));
        assert!(text.contains(SITE));
        assert!(text.contains(COMMAND));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        let lower = text.to_ascii_lowercase();
        assert!(!lower.contains("k2"));
        assert!(!lower.contains("kessel"));
    }

    #[test]
    fn help_types_names_session_and_turn() {
        let text = help_types_text();
        assert!(text.contains("session"));
        assert!(text.contains("turn"));
        assert!(text.contains("terminal harness"));
        assert!(text.contains("Grok Bot"));
        assert!(text.contains("Sand"));
        assert!(text.contains("live"));
        assert!(text.contains("tray"));
        assert!(text.contains("not types"));
    }

    #[test]
    fn help_is_p5_not_k2() {
        let text = help_text();
        assert!(text.contains("p5"));
        assert!(text.contains("Postal"));
        assert!(text.contains("postal.bot"));
        assert!(text.contains("whoami"));
        assert!(text.contains("inbox"));
        assert!(text.contains("sent"));
        assert!(text.contains("outbox"));
        assert!(!text.contains("k2 "));
        assert!(!text.to_ascii_lowercase().contains("kessel"));
    }
}
