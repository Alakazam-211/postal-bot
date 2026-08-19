use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use p5_core::{default_root, DeliveryMode, MailItem, Mailbox, MailboxError, PeerType};

mod agent;
mod control;
mod http;
mod pair;
mod service;
mod session_map;
mod sm;

use pair::{
    finish as finish_pair, run_accept, run_add, run_list, run_login, run_me, run_reject,
    run_revoke, run_show,
};
use sm::{send_msg, MsgRequest, MsgResponse, SmContext, SmError};

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
    /// Send a message (local copy first; auto-wakes)
    Msg {
        /// Destination `handle::sub.postal.bot`
        addr: String,
        /// Message body
        text: String,
        /// Do not wake a dormant session
        #[arg(long)]
        no_wake: bool,
        /// Print a JSON object
        #[arg(long)]
        json: bool,
        /// Display From (not identity)
        #[arg(long)]
        from: Option<String>,
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
    /// Resident agent (loopback inbound + UDS control)
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Install the agent; optional Connect token (`--token k2c_…`)
    Login {
        /// Connect token (`k2c_…`)
        #[arg(long)]
        token: Option<String>,
        /// Write the unit file without loading it
        #[arg(long, hide = true)]
        no_start: bool,
    },
    /// Stop and unload the resident agent
    Logout,
    /// Agent / tunnel status (UDS)
    Status,
    /// Pairing (plane). `add` may request; accept/reject/revoke are owner-gated
    Pair {
        #[command(subcommand)]
        action: PairAction,
    },
    /// Publish this handle's public pairing key (`PUT /postal/me`)
    Me {
        /// Display / pairing address (`handle::sub.postal.bot`)
        #[arg(long)]
        from: Option<String>,
        /// Our type: session or turn (default session — this CLI's identity)
        #[arg(long)]
        typ: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PairAction {
    /// Request a pair (also publishes `/postal/me`)
    Add {
        /// Peer `handle::sub.postal.bot`
        addr: String,
        /// Our address
        #[arg(long)]
        from: Option<String>,
        /// Our type: session or turn (default session — this CLI's identity)
        #[arg(long)]
        typ: Option<String>,
    },
    /// List pairs (updates the local roster)
    List {
        /// Inbox only
        #[arg(long)]
        inbox: bool,
    },
    /// Review a pair (SAS, both addrs, status)
    Show {
        /// Pair id
        id: String,
    },
    /// Accept (owner-gated unless `P5_OWNER_PAIR=1`)
    Accept {
        /// Pair id
        id: String,
        /// SAS digits (else computed from local + peer keys)
        #[arg(long)]
        sas: Option<String>,
    },
    /// Reject (owner-gated unless `P5_OWNER_PAIR=1`)
    Reject {
        /// Pair id
        id: String,
    },
    /// Revoke (owner-gated unless `P5_OWNER_PAIR=1`)
    Revoke {
        /// Pair id
        id: String,
    },
>>>>>>> d56f3a8 (P5-8: pairing UX against CP-3)
}

#[derive(Debug, Subcommand)]
enum InboxAction {
    /// List items (optional folder: active, done, …)
    List { folder: Option<String> },
    /// Print a cover
    Read { id: String },
    /// Reply to the item's From (`p5 msg <from>`)
    Respond {
        /// Inbox item id
        id: String,
        /// Message body
        text: String,
        /// Do not wake a dormant session
        #[arg(long)]
        no_wake: bool,
        /// Print a JSON object
        #[arg(long)]
        json: bool,
        /// Display From (not identity)
        #[arg(long)]
        from: Option<String>,
    },
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

#[derive(Debug, Subcommand)]
enum AgentAction {
    /// Start the resident agent (blocks)
    Run,
    /// Signal the running agent (pid file + UDS)
    Stop,
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
        Some(InboxAction::Respond { .. }) => {
            unreachable!("respond is handled in main")
        }
    }
}

fn emit_msg(resp: &MsgResponse, json: bool) {
    if json {
        println!("{}", resp.to_json());
        return;
    }
    if resp.success {
        println!("{}", resp.pretty_line());
    } else {
        eprintln!("{}", resp.pretty_line());
    }
}

fn run_msg(req: MsgRequest, json: bool) {
    let root = default_root();
    match control::try_send_msg(&root, &req) {
        control::TrySend::Up(resp) => {
            emit_msg(&resp, json);
            std::process::exit(resp.exit_code());
        }
        control::TrySend::Down => {}
    }
    eprintln!("{}", control::agent_down_hint());
    let ctx = match SmContext::load_default() {
        Ok(ctx) => ctx,
        Err(err) => {
            fail_sm(err, json);
        }
    };
    match send_msg(&ctx, &req) {
        Ok(resp) => {
            emit_msg(&resp, json);
            std::process::exit(resp.exit_code());
        }
        Err(err) => fail_sm(err, json),
    }
}

fn fail_sm(err: SmError, json: bool) -> ! {
    if json {
        let resp = MsgResponse {
            success: false,
            id: None,
            to: None,
            status: None,
            target_session_id: None,
            attempts: 0,
            reason: Some("error".into()),
            hint: Some(err.to_string()),
            woke: false,
            wake_ms: None,
            already: false,
        };
        println!("{}", resp.to_json());
    } else {
        eprintln!("{err}");
    }
    std::process::exit(err.exit_code());
}

fn inbox_respond(id: String, text: String, no_wake: bool, json: bool, from: Option<String>) {
    let mb = mailbox();
    match mb.read_inbox(&id) {
        Ok(item) => run_msg(
            MsgRequest {
                to: item.from.to_string(),
                body: text,
                no_wake,
                from,
            },
            json,
        ),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(err.exit_code());
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
        Commands::Msg {
            addr,
            text,
            no_wake,
            json,
            from,
        } => run_msg(
            MsgRequest {
                to: addr,
                body: text,
                no_wake,
                from,
            },
            json,
        ),
        Commands::Inbox {
            action:
                Some(InboxAction::Respond {
                    id,
                    text,
                    no_wake,
                    json,
                    from,
                }),
        } => inbox_respond(id, text, no_wake, json, from),
        Commands::Inbox { action } => run_mailbox(inbox_cmd(action)),
        Commands::Sent { action } => run_mailbox(sent_cmd(action)),
        Commands::Outbox { action } => run_mailbox(outbox_cmd(action)),
        Commands::Agent {
            action: AgentAction::Run,
        } => {
            if let Err(err) = agent::run() {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Commands::Agent {
            action: AgentAction::Stop,
        } => {
            if let Err(err) = agent::stop() {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Commands::Login { token, no_start } => {
            if let Some(token) = token {
                finish_pair(run_login(token));
            }
            match agent::login(no_start) {
                Ok(path) => println!("wrote {}", path.display()),
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Logout => {
            if let Err(err) = agent::logout() {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Commands::Status => print!("{}", agent::status_text()),
        Commands::Pair {
            action: PairAction::Add { addr, from, typ },
        } => finish_pair(run_add(addr, from, typ)),
        Commands::Pair {
            action: PairAction::List { inbox },
        } => finish_pair(run_list(inbox)),
        Commands::Pair {
            action: PairAction::Show { id },
        } => finish_pair(run_show(id)),
        Commands::Pair {
            action: PairAction::Accept { id, sas },
        } => finish_pair(run_accept(id, sas)),
        Commands::Pair {
            action: PairAction::Reject { id },
        } => finish_pair(run_reject(id)),
        Commands::Pair {
            action: PairAction::Revoke { id },
        } => finish_pair(run_revoke(id)),
        Commands::Me { from, typ } => finish_pair(run_me(from, typ)),
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
        assert!(text.contains("msg"));
        assert!(text.contains("pair"));
        assert!(text.contains("me"));
        assert!(!text.contains("k2 "));
        assert!(!text.to_ascii_lowercase().contains("kessel"));
    }
}
