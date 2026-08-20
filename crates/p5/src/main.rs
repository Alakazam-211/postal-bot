use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use p5_core::{default_root, DeliveryMode, MailItem, Mailbox, MailboxError, PeerType};

mod agent;
mod billing;
mod control;
mod hold;
mod http;
mod k2;
mod last_mile;
mod pair;
mod service;
mod session_map;
mod sm;
mod turn;

mod handle;
mod login;

use pair::{
    finish as finish_pair, run_accept, run_add, run_list, run_me, run_reject, run_revoke,
    run_set_key, run_show,
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
    after_help = "Product: Postal / postal.bot. Command: p5.\nSource (MIT): https://github.com/Alakazam-211/postal-bot — review the code, send last-mile plugin PRs.\nSee also: p5 help types, p5 help last-mile",
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
    /// Show help, or a topic (`p5 help types`, `p5 help last-mile`)
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
    /// Sign in (device code) and pick this computer's hostname
    Login {
        /// Connect token (`k2c_…`). Skips device approval.
        #[arg(long)]
        token: Option<String>,
        /// Bind this computer to this subdomain now (`acme` → `acme.postal.bot`).
        /// Use when you already know which hostname the human wants (scripts).
        /// Skips asking. Alias: `--host`.
        #[arg(long, visible_alias = "host")]
        label: Option<String>,
        /// Print the approval URL; do not try to open a browser (remote servers)
        #[arg(long)]
        no_browser: bool,
        /// Write the unit file without loading it
        #[arg(long, hide = true)]
        no_start: bool,
    },
    /// Stop and unload the resident agent
    Logout,
    /// Agent / tunnel status (UDS)
    Status,
    /// Bind a handle to this session's plugin + re-wake identity
    Handle {
        #[command(subcommand)]
        action: HandleAction,
    },
    /// Pairing (plane). `add` may request; accept/reject/revoke are owner-gated
    Pair {
        #[command(subcommand)]
        action: PairAction,
    },
    /// Pull held mail from the plane (one shot; requires `P5_HOLD=1`)
    Recv,
    /// Messages sent this month on this enrolled subdomain
    Usage {
        /// Print a JSON object
        #[arg(long)]
        json: bool,
    },
    /// Account plan (1 free postal.bot subdomain, 100 msgs, $2.99/mo extra)
    Billing {
        #[command(subcommand)]
        action: Option<BillingAction>,
    },
    /// Publish this handle's public pairing key (`PUT /postal/me`)
    Me {
        /// Our type: session or turn (default session — this CLI's identity)
        #[arg(long)]
        typ: Option<String>,
        /// Also print the public SPKI PEM (safe to share)
        #[arg(long)]
        pem: bool,
    },
}

#[derive(Debug, Subcommand)]
enum HandleAction {
    /// Pack plugin + session id for this handle (run in that bot's terminal)
    Claim {
        /// Left side of `handle::host` (`claude`)
        handle: String,
        /// Last-mile plugin (`k2`, `grok`, or exec name)
        #[arg(long)]
        plugin: Option<String>,
        /// Workspace directory (default: cwd)
        #[arg(long)]
        cwd: Option<String>,
        /// Platform session id; plugin must validate it
        #[arg(long)]
        session: Option<String>,
        /// session or turn (default: plugin claim)
        #[arg(long)]
        typ: Option<String>,
        /// Replace an existing session id on this handle
        #[arg(long)]
        force: bool,
        /// Print a JSON object
        #[arg(long)]
        json: bool,
    },
    /// List homes rows (address, plugin, session, cwd)
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one handle
    Show {
        handle: String,
        #[arg(long)]
        json: bool,
    },
    /// Remove a homes row (owner-gated: `P5_OWNER_PAIR=1`)
    Drop { handle: String },
}

#[derive(Debug, Subcommand)]
enum PairAction {
    /// Request a pair (also publishes `/postal/me`)
    Add {
        /// Peer `handle::sub.postal.bot`
        addr: String,
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
    /// Store a peer's public SPKI on the local roster (plane list omits keys)
    SetKey {
        /// Peer `handle::sub.postal.bot`
        addr: String,
        /// PEM file (`-` = stdin)
        #[arg(long = "pem-file")]
        pem_file: Option<String>,
    },
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

#[derive(Debug, Subcommand)]
enum BillingAction {
    /// Print plan, remaining, and the payment URL
    Show,
    /// Apply a paid entitlement id from the k2.dev / postal.bot account
    Redeem {
        /// Checkout session id
        session: String,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum HelpTopic {
    /// Bot types: session and turn (live/tray are modes)
    Types,
    /// Last-mile plugins (`homes.harness`): k2, grok, exec
    #[value(name = "last-mile", alias = "plugins", alias = "grok")]
    LastMile,
    /// 1 free postal.bot subdomain (100 msgs/mo); extra labels $2.99/mo
    Usage,
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

Last mile (how a live cell is knocked after inbox fsync) is a plugin
on homes.harness. See: p5 help last-mile
"
    )
}

fn help_last_mile_text() -> String {
    format!(
        "\
Last mile — after Postal writes ~/.postal/inbox, knock the live agent.

Pack plugin + session per handle (not per install):

  p5 handle claim <handle> --plugin k2|grok|<name> [--json]

Run that in the bot's own terminal. See also: p5 help types

Built-in  grok  (Grok Bot / Sand, usually type turn)
  Loopback gateway HTTP (same contract as Grok Bot's host API):
  POST http://127.0.0.1:<port>/api/listAgents     body {{}}
  POST http://127.0.0.1:<port>/api/sendPrompt     body {{agentId, prompt, clientNonce}}
  GET  http://127.0.0.1:<port>/health             HOST UP (public)
  Auth on /api/*: Authorization: Bearer <token>
        token + port from $SAND_DATA_ROOT/gateway.json
        (default ~/sand-data/gateway.json, written by the Grok Bot host).
        host 0.0.0.0/:: is rewritten to 127.0.0.1. Never dial a remote Sand.
        override: P5_TURN_TOKEN / P5_TURN_HEALTH / P5_TURN_PROMPT / P5_TURN_AGENT_ID
  agentId: Sand UUID — never the Postal handle \"grok\".
        1. P5_TURN_AGENT_ID
        2. homes.session_id if it is a UUID
        3. POST listAgents name match (handle grok → agent \"Grok\")
        4. ~/sand-data/agents/<uuid>/profile.json
        5. GET /health activeAgentId
  Prompt: [from handle::host] <body>
        No [p5] tag — Postal is its own product. Do not send unauthenticated (HTTP 401).
  Mail is already in ~/.postal/inbox even if sendPrompt fails.
  One sendPrompt = one billed Grok Bot turn. Rate-limit 12/hour/peer.

Built-in  k2  (K2 workspace, type session)
  POST /cli/workspace/msg on the local k2-daemon (same route as k2 msg).
  Auth: ~/.k2/daemon.port + daemon.token (P5_K2_MSG=0 disables)
  Target: homes.cwd if it is an absolute path, else the Postal handle.
  Knock text: the mail body (k2 stamps [from <addr>]). Tray stays ~/.postal/inbox.
  wake=true unless the sender passed --no-wake.

Exec plugin  (anything else)
  Executable: $P5_HARNESS_DIR/<name>  or  ~/.postal/harness/<name>
              or p5-harness-<name> on PATH
  argv: <plugin> knock
  stdin: Knock JSON v1 (id, to, from, handle, typ, title, text, body, wake, cwd)
  exit 0 / {{\"ok\":true}} = hit. Tray is already durable on failure.
  Example: repo harness/webhook  (P5_WEBHOOK_URL)

Setup on a Grok Bot box (receiving):
  curl … https://www.postal.bot/install.sh | sh   # p5 + frpc beside it
  p5 login     # or p5 agent run if systemd user bus is missing
  p5 status    # agent: up  tunnel: up
  homes.harness=grok  typ=turn  address=grok::this-label.postal.bot
  Need a running Grok Bot host so ~/sand-data/gateway.json exists.

p5 status / agent.log: \"turn gateway HTTP 401\" or \"token missing\" means
the plugin ran but Sand auth failed — not a pairing failure.

Source (MIT): https://github.com/Alakazam-211/postal-bot
New bot last-miles: harness/ + CONTRIBUTING.md (inject Knock JSON body).
"
    )
}

fn help_usage_text() -> String {
    format!(
        "\
Usage — same account as k2.dev. Free on postal.bot only: {subs}
subdomain with {msgs} messages/month (k2.dev has no free label —
websockets cost more). Extra labels ${price}/mo, same Stripe
portal as K2 Connect. See {pay}

  p5 usage           sent / remaining / subdomains for this host
  p5 usage --json
  p5 billing         same readout plus the account URL

A paid label bought on k2.dev or postal.bot hits the same Stripe
checkout ({checkout}) and syncs. Create the account at {signup}.
Mail from before billing first ran on this box does not count.

Over the free message cap, p5 msg exits 3 (quota). P5_BILLING=0
shows usage but does not block send.
",
        msgs = crate::billing::FREE_LIMIT,
        subs = crate::billing::FREE_SUBDOMAINS,
        price = crate::billing::PRICE_USD,
        pay = crate::billing::pay_url(),
        signup = crate::billing::SIGNUP_URL,
        checkout = crate::billing::checkout_url(),
    )
}

fn run_usage(json: bool) {
    match crate::billing::collect(&default_root()) {
        Ok(report) => {
            if json {
                println!("{}", serde_json::to_string(&report).expect("usage json"));
            } else {
                print!("{}", crate::billing::usage_text(&report));
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(err.exit_code());
        }
    }
}

fn run_billing(action: Option<BillingAction>) {
    match action {
        None | Some(BillingAction::Show) => run_usage(false),
        Some(BillingAction::Redeem { session }) => {
            match crate::billing::redeem(&default_root(), &session) {
                Ok(report) => print!("{}", crate::billing::usage_text(&report)),
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(err.exit_code());
                }
            }
        }
    }
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

fn run_handle(action: HandleAction) {
    let result = match action {
        HandleAction::Claim {
            handle,
            plugin,
            cwd,
            session,
            typ,
            force,
            json,
        } => crate::handle::run_claim(handle, plugin, cwd, session, typ, json, force),
        HandleAction::List { json } => crate::handle::run_list(json),
        HandleAction::Show { handle, json } => crate::handle::run_show(handle, json),
        HandleAction::Drop { handle } => crate::handle::run_drop(handle),
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(err.exit_code());
    }
}

fn inbox_respond(id: String, text: String, no_wake: bool, json: bool) {
    let mb = mailbox();
    match mb.read_inbox(&id) {
        Ok(item) => run_msg(
            MsgRequest {
                to: item.from.to_string(),
                body: text,
                no_wake,
                cwd: None,
                session_ids: Vec::new(),
            }
            .capture_caller(),
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
        Commands::Help {
            topic: Some(HelpTopic::LastMile),
        } => print!("{}", help_last_mile_text()),
        Commands::Help {
            topic: Some(HelpTopic::Usage),
        } => print!("{}", help_usage_text()),
        Commands::Handle { action } => run_handle(action),
        Commands::Usage { json } => run_usage(json),
        Commands::Billing { action } => run_billing(action),
        Commands::Msg {
            addr,
            text,
            no_wake,
            json,
        } => run_msg(
            MsgRequest {
                to: addr,
                body: text,
                no_wake,
                cwd: None,
                session_ids: Vec::new(),
            }
            .capture_caller(),
            json,
        ),
        Commands::Inbox {
            action:
                Some(InboxAction::Respond {
                    id,
                    text,
                    no_wake,
                    json,
                }),
        } => inbox_respond(id, text, no_wake, json),
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
        Commands::Login {
            token,
            label,
            no_browser,
            no_start,
        } => {
            if let Err(err) = login::run(token, label, no_browser) {
                eprintln!("{err}");
                std::process::exit(err.exit_code());
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
            action: PairAction::Add { addr, typ },
        } => finish_pair(run_add(addr, typ)),
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
        Commands::Pair {
            action: PairAction::SetKey { addr, pem_file },
        } => finish_pair(run_set_key(addr, pem_file)),
        Commands::Me { typ, pem } => finish_pair(run_me(typ, pem)),
        Commands::Recv => match hold::run_recv() {
            Ok(report) => println!("pulled {}", report.pulled),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(err.exit_code());
            }
        },
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
        assert!(text.contains("p5 help last-mile"));
    }

    #[test]
    fn help_last_mile_documents_grok_gateway() {
        let text = help_last_mile_text();
        assert!(text.contains("sendPrompt"));
        assert!(text.contains("listAgents"));
        assert!(text.contains("sand-data/gateway.json"));
        assert!(text.contains("Authorization: Bearer"));
        assert!(text.contains("activeAgentId"));
        assert!(text.contains("cli/workspace/msg"));
        assert!(text.contains("Knock JSON v1"));
        assert!(text.contains("401"));
        assert!(text.contains("[p5]"));
        assert!(text.contains("homes.harness"));
        assert!(!text.contains("[k2g]"));
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
        assert!(text.contains("recv"));
        assert!(text.contains("usage"));
        assert!(text.contains("billing"));
        assert!(text.contains("https://github.com/Alakazam-211/postal-bot"));
        assert!(text.contains("review the code"));
        assert!(!text.contains("k2 "));
        assert!(!text.to_ascii_lowercase().contains("kessel"));
    }

    #[test]
    fn help_usage_names_free_tier_and_price() {
        let text = help_usage_text();
        assert!(text.contains("100"));
        assert!(text.contains("2.99"));
        assert!(text.contains("p5 usage"));
        assert!(text.contains("postal.bot/account"));
        assert!(text.contains("subdomain"));
        assert!(text.contains("k2.dev"));
        assert!(text.contains("k2.dev/pricing"));
        assert!(text.contains("postal.bot only"));
        assert!(!text.contains("9.99"));
        assert!(!text.contains("[k2g]"));
    }
}
