//! WireGuard without wg-quick. The helper starts wireguard-go from the VPN
//! runtime, configures it over its socket, and sets up the tunnel's
//! addresses, MTU and routes itself. It is behind `WgConnectArgs::native`
//! until it has carried every kind of profile; wg-quick stays the default.
//!
//! What wg-quick did for SuperManager's configs, and where it is here:
//!
//! - `wireguard-go utun` takes a free utunN and writes its name to
//!   `/var/run/wireguard/<name>.name`, where status finds it: [`start`].
//! - `wg addconf`: [`uapi::set`], with each endpoint resolved first.
//! - `ifconfig`: the addresses; the MTU, the config's or the primary
//!   interface's less 80; up.
//! - A route per AllowedIPs prefix, the most specific first, unless the
//!   tunnel already carries it. All of IPv4 or IPv6 becomes its two
//!   halves, which win over the default route without replacing it; each
//!   peer's endpoint then keeps a host route the way the default route
//!   goes, so the tunnel's own packets stay out of the tunnel.
//! - A supervisor that moves the endpoint routes and the MTU with the
//!   network, and cleans up when the tunnel goes: [`supervise`].
//! - Down: without its socket wireguard-go exits, and the utun and every
//!   route through it go with it.
//!
//! DNS is the helper's own either way (`dns::set_vpn_dns`). There are no
//! hooks, and no config file with the private key on disk: the key goes
//! from the RPC to wireguard-go's socket.
//!
//! wireguard-go runs in its own session, so a helper restart leaves the
//! tunnel up. The next helper finds it in [`STATE_DIR`] and supervises it.

mod conf;
mod net;
mod uapi;

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::process::Child;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use conf::Config;
use net::Via;

/// What the helper knows about each tunnel it set up, for the helper after
/// it. Root-only, and gone at boot with the tunnels.
const STATE_DIR: &str = "/var/run/com.sybr.supermanager.wireguard";
/// wireguard-go's: the `<utun>.sock` sockets, and the name files.
const RUN_DIR: &str = "/var/run/wireguard";
/// wireguard-go has its utun and socket up in well under a second.
const START_TIMEOUT: Duration = Duration::from_secs(5);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct State {
    name: String,
    interface: String,
    /// wireguard-go's.
    pid: i32,
    /// The config's MTU. None follows the primary interface's.
    mtu: Option<u32>,
    /// AllowedIPs take all of IPv4 / IPv6, so endpoints need host routes.
    all4: bool,
    all6: bool,
    #[serde(default)]
    endpoint_routes: EndpointRoutes,
}

impl State {
    fn path(name: &str) -> PathBuf {
        Path::new(STATE_DIR).join(format!("{name}.json"))
    }

    fn load(name: &str) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(Self::path(name)).ok()?).ok()
    }

    fn save(&self) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(STATE_DIR)
            .with_context(|| format!("create {STATE_DIR}"))?;
        crate::private_file::write(&Self::path(&self.name), &serde_json::to_vec(self)?)
            .with_context(|| format!("write {}", Self::path(&self.name).display()))
    }

    fn remove(&self) {
        let _ = std::fs::remove_file(Self::path(&self.name));
    }
}

/// The host routes that keep endpoints out of the tunnel, and which way
/// the default routes went when they were added.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct EndpointRoutes {
    via4: Option<Via>,
    via6: Option<Via>,
    routed: Vec<IpAddr>,
}

/// A tunnel's supervisor, which also takes the tunnel down.
pub struct Tunnel {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// Whether the helper set up the tunnel `name` itself.
pub fn exists(name: &str) -> bool {
    State::path(name).exists()
}

fn name_file(name: &str) -> PathBuf {
    Path::new(RUN_DIR).join(format!("{name}.name"))
}

/// The utun wireguard-go says it took.
fn read_name_file(name: &str) -> Option<String> {
    let interface = std::fs::read_to_string(name_file(name)).ok()?;
    let interface = interface.trim();
    let number = interface.strip_prefix("utun")?;
    (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())).then(|| interface.to_owned())
}

/// Set up the tunnel `name` as `text`, a rendered config, says. Returns its
/// utun and its supervisor.
pub async fn up(name: &str, text: &str) -> Result<(String, Tunnel)> {
    let config = conf::parse(text).context("the WireGuard config")?;
    let program = crate::vpn_runtime::wireguard_go()?;
    let endpoints = resolve(&config).await?;
    let (interface, child) = start(name, &program).await?;
    let mut state = State {
        name: name.to_owned(),
        interface: interface.clone(),
        pid: child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .unwrap_or(0),
        mtu: config.mtu,
        all4: false,
        all6: false,
        endpoint_routes: EndpointRoutes::default(),
    };
    if let Err(e) = configure(&mut state, &config, &endpoints).await {
        teardown(&state, Some(child)).await;
        return Err(e);
    }
    Ok((interface, supervise(state, Some(child))))
}

/// Each peer's endpoint as an address. Resolved before anything changes:
/// with the routes in, a name might only resolve through the tunnel.
async fn resolve(config: &Config) -> Result<Vec<Option<SocketAddr>>> {
    let mut resolved = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        let Some(endpoint) = &peer.endpoint else {
            resolved.push(None);
            continue;
        };
        let lookup = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port));
        let address = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
            .await
            .map_err(|_| anyhow!("{} did not resolve in time", endpoint.host))?
            .with_context(|| format!("resolve {}", endpoint.host))?
            .next()
            .ok_or_else(|| anyhow!("{} has no address", endpoint.host))?;
        resolved.push(Some(address));
    }
    Ok(resolved)
}

/// Start wireguard-go on a utun of its choosing. Returns the utun once its
/// configuration socket is there.
async fn start(name: &str, program: &Path) -> Result<(String, Child)> {
    use std::os::unix::process::CommandExt as _;
    // wireguard-go writes the name file before it creates this itself.
    std::fs::create_dir_all(RUN_DIR).with_context(|| format!("create {RUN_DIR}"))?;
    let _ = std::fs::remove_file(name_file(name));
    let mut command = tokio::process::Command::new(program);
    command
        .args(["-f", "utun"])
        .env_clear()
        .env("WG_TUN_NAME_FILE", name_file(name))
        // stdout and stderr stay the helper's, which launchd writes to
        // the helper log.
        .stdin(std::process::Stdio::null());
    // Its own session, out of the helper's process group: launchd stops
    // that group together with the helper, and the tunnel must stay up.
    // SAFETY: setsid is async-signal-safe and touches no memory.
    unsafe {
        command.as_std_mut().pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("start {}", program.display()))?;
    let deadline = Instant::now() + START_TIMEOUT;
    let failure = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break anyhow!(
                    "wireguard-go stopped as it started ({status}); the helper log says why"
                )
            }
            Ok(None) => {}
            Err(e) => break anyhow!("wireguard-go: {e}"),
        }
        if let Some(interface) = read_name_file(name) {
            if uapi::answers(&interface).await {
                return Ok((interface, child));
            }
        }
        if Instant::now() >= deadline {
            break anyhow!(
                "wireguard-go had no interface after {}s",
                START_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let _ = child.kill().await;
    let _ = std::fs::remove_file(name_file(name));
    Err(failure)
}

async fn configure(
    state: &mut State,
    config: &Config,
    endpoints: &[Option<SocketAddr>],
) -> Result<()> {
    state.save()?;
    let interface = state.interface.clone();
    uapi::set(&interface, config, endpoints).await?;
    for address in &config.addresses {
        net::add_address(&interface, address).await?;
    }
    apply_mtu(state).await?;
    net::up(&interface).await?;

    let plan = plan_routes(config.peers.iter().flat_map(|peer| &peer.allowed_ips));
    state.all4 = plan.all4;
    state.all6 = plan.all6;
    // The endpoint routes first, so there is no moment the halves would
    // take a handshake into the tunnel.
    refresh_endpoint_routes(state).await;
    state.save()?;
    for net in &plan.routes {
        if !net::routed_via(net, &interface).await {
            net::add_route(net, &interface).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RoutePlan {
    routes: Vec<IpNet>,
    all4: bool,
    all6: bool,
}

/// The routes for a tunnel's AllowedIPs, the most specific first, as
/// wg-quick added them: all of IPv4 or IPv6 as its two halves.
fn plan_routes<'a>(allowed: impl IntoIterator<Item = &'a IpNet>) -> RoutePlan {
    let mut nets: Vec<IpNet> = allowed
        .into_iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    nets.sort_by_key(|net| std::cmp::Reverse(net.prefix_len()));
    let halves = |a: &str, b: &str| [a, b].map(|half| half.parse::<IpNet>().expect("a prefix"));
    let mut plan = RoutePlan::default();
    for net in nets {
        match net {
            IpNet::V4(_) if net.prefix_len() == 0 => {
                plan.all4 = true;
                plan.routes.extend(halves("0.0.0.0/1", "128.0.0.0/1"));
            }
            IpNet::V6(_) if net.prefix_len() == 0 => {
                plan.all6 = true;
                plan.routes.extend(halves("::/1", "8000::/1"));
            }
            _ => plan.routes.push(net),
        }
    }
    plan
}

/// The config's MTU, or the primary interface's less 80 for WireGuard's
/// own headers, as wg-quick chose it.
async fn apply_mtu(state: &State) -> Result<()> {
    let mtu = match state.mtu {
        Some(mtu) => mtu,
        None => {
            let base = match net::default_route(true).await.1 {
                Some(primary) => net::mtu(&primary).await,
                None => None,
            };
            base.unwrap_or(1500).saturating_sub(80)
        }
    };
    if net::mtu(&state.interface).await != Some(mtu) {
        net::set_mtu(&state.interface, mtu).await?;
    }
    Ok(())
}

struct EndpointChanges {
    delete: Vec<IpAddr>,
    add: Vec<(IpAddr, Via)>,
    next: EndpointRoutes,
}

/// wg-quick's `set_endpoint_direct_route`: a host route for each endpoint
/// in a family the tunnel takes whole, the way that family's default
/// route goes. A route whose way out changed is replaced; an endpoint no
/// longer used loses its route.
fn plan_endpoint_routes(
    current: &EndpointRoutes,
    via4: &Via,
    via6: &Via,
    endpoints: &[IpAddr],
    all4: bool,
    all6: bool,
) -> EndpointChanges {
    let via = |ip: &IpAddr| if ip.is_ipv4() { via4 } else { via6 };
    let was = |ip: &IpAddr| {
        if ip.is_ipv4() {
            current.via4.as_ref()
        } else {
            current.via6.as_ref()
        }
    };
    let wanted: BTreeSet<IpAddr> = endpoints
        .iter()
        .copied()
        .filter(|ip| if ip.is_ipv4() { all4 } else { all6 })
        .collect();
    let mut delete = Vec::new();
    let mut kept = BTreeSet::new();
    for ip in &current.routed {
        if wanted.contains(ip) && was(ip) == Some(via(ip)) {
            kept.insert(*ip);
        } else {
            delete.push(*ip);
        }
    }
    let add = wanted
        .iter()
        .filter(|ip| !kept.contains(*ip))
        .map(|ip| (*ip, via(ip).clone()))
        .collect();
    EndpointChanges {
        delete,
        add,
        next: EndpointRoutes {
            via4: Some(via4.clone()),
            via6: Some(via6.clone()),
            routed: wanted.into_iter().collect(),
        },
    }
}

/// Bring the endpoint routes in line with the network and the peers now.
/// Returns whether anything changed.
async fn refresh_endpoint_routes(state: &mut State) -> bool {
    if !state.all4 && !state.all6 {
        return false;
    }
    let endpoints = match uapi::endpoints(&state.interface).await {
        Ok(endpoints) => endpoints,
        Err(e) => {
            tracing::warn!(interface = %state.interface, "WireGuard endpoints: {e:#}");
            return false;
        }
    };
    let (via4, _) = net::default_route(true).await;
    let (via6, _) = net::default_route(false).await;
    let changes = plan_endpoint_routes(
        &state.endpoint_routes,
        &via4,
        &via6,
        &endpoints,
        state.all4,
        state.all6,
    );
    if changes.delete.is_empty() && changes.add.is_empty() && changes.next == state.endpoint_routes
    {
        return false;
    }
    for ip in &changes.delete {
        net::delete_host_route(*ip).await;
    }
    for (ip, via) in &changes.add {
        if let Err(e) = net::add_host_route(*ip, via).await {
            tracing::warn!("WireGuard endpoint route: {e:#}");
        }
    }
    state.endpoint_routes = changes.next;
    true
}

/// Keep the tunnel's endpoint routes and MTU in line with the network,
/// and take the tunnel down when told to or once it is gone.
fn supervise(mut state: State, mut child: Option<Child>) -> Tunnel {
    let (stop, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut events = net::RouteEvents::default();
        let why = loop {
            tokio::select! {
                request = &mut stopped => {
                    if request.is_err() {
                        // Nobody holds the handle any more: the helper is
                        // going, and the tunnel stays up for the next one.
                        return;
                    }
                    break "disconnect";
                }
                status = exited(&mut child) => {
                    tracing::warn!(interface = %state.interface, "wireguard-go exited: {status:?}");
                    break "wireguard-go exited";
                }
                () = events.changed() => {
                    if !net::exists(&state.interface) {
                        break "its interface is gone";
                    }
                    if refresh_endpoint_routes(&mut state).await {
                        if let Err(e) = state.save() {
                            tracing::warn!("{e:#}");
                        }
                    }
                    if state.mtu.is_none() {
                        if let Err(e) = apply_mtu(&state).await {
                            tracing::warn!("WireGuard MTU: {e:#}");
                        }
                    }
                }
            }
        };
        tracing::info!(tunnel = %state.name, interface = %state.interface, "WireGuard tunnel down: {why}");
        teardown(&state, child).await;
    });
    Tunnel { stop, task }
}

async fn exited(child: &mut Option<Child>) -> std::io::Result<std::process::ExitStatus> {
    match child {
        Some(child) => child.wait().await,
        None => std::future::pending().await,
    }
}

/// Take the tunnel down and clean up after it. wireguard-go exits when its
/// socket goes, and the utun and every route through it go with it; the
/// endpoint routes, which go the default route's way, do not.
async fn teardown(state: &State, mut child: Option<Child>) {
    let _ = std::fs::remove_file(uapi::socket(&state.interface));
    if !gone(&state.interface, Duration::from_secs(3)).await {
        tracing::warn!(interface = %state.interface, "wireguard-go is still running without its socket; stopping it");
        match child.as_mut() {
            Some(child) => {
                let _ = child.kill().await;
            }
            None => {
                let program = Path::new(crate::vpn_runtime::RUNTIME_DIR).join("wireguard-go");
                if crate::proc::process_is(state.pid, &program) {
                    // SAFETY: a signal to the pid just seen running wireguard-go.
                    unsafe {
                        libc::kill(state.pid, libc::SIGKILL);
                    }
                }
            }
        }
        if !gone(&state.interface, Duration::from_secs(2)).await {
            tracing::error!(interface = %state.interface, "the WireGuard interface is still there");
        }
    }
    if let Some(mut child) = child {
        let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    }
    for ip in &state.endpoint_routes.routed {
        net::delete_host_route(*ip).await;
    }
    let _ = std::fs::remove_file(name_file(&state.name));
    state.remove();
}

async fn gone(interface: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while net::exists(interface) {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// Take the tunnel `name` down, through its supervisor when it has one.
/// An error when its interface is still there afterwards.
pub async fn down(name: &str, tunnel: Option<Tunnel>) -> Result<()> {
    let interface = State::load(name).map(|state| state.interface);
    if let Some(tunnel) = tunnel {
        let _ = tunnel.stop.send(());
        if tokio::time::timeout(Duration::from_secs(10), tunnel.task)
            .await
            .is_err()
        {
            tracing::warn!(tunnel = name, "the WireGuard supervisor did not finish");
        }
    }
    // Nobody supervised it, or the supervisor did not get to the end.
    if let Some(state) = State::load(name) {
        teardown(&state, None).await;
    }
    match interface {
        Some(interface) if net::exists(&interface) => bail!("{interface} is still up"),
        _ => Ok(()),
    }
}

/// The tunnels an earlier helper set up and left running: supervise each
/// that is still up, and clean up after each that is not.
pub async fn adopt() -> HashMap<String, Tunnel> {
    let mut tunnels = HashMap::new();
    let Ok(entries) = std::fs::read_dir(STATE_DIR) else {
        return tunnels;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(state) = path
            .file_name()
            .and_then(|file| file.to_str())
            .and_then(|file| file.strip_suffix(".json"))
            .and_then(State::load)
        else {
            continue;
        };
        if net::exists(&state.interface) && uapi::answers(&state.interface).await {
            tracing::info!(tunnel = %state.name, interface = %state.interface, "supervising the WireGuard tunnel an earlier helper set up");
            tunnels.insert(state.name.clone(), supervise(state, None));
        } else {
            tracing::info!(tunnel = %state.name, "cleaning up after a WireGuard tunnel that is gone");
            teardown(&state, None).await;
        }
    }
    tunnels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|net| net.parse().unwrap()).collect()
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|ip| ip.parse().unwrap()).collect()
    }

    #[test]
    fn all_of_a_family_becomes_its_two_halves() {
        let allowed = nets(&[
            "0.0.0.0/0",
            "10.1.2.3/32",
            "::/0",
            "10.0.0.0/8",
            "10.0.0.0/8",
        ]);
        assert_eq!(
            plan_routes(&allowed),
            RoutePlan {
                routes: nets(&[
                    "10.1.2.3/32",
                    "10.0.0.0/8",
                    "0.0.0.0/1",
                    "128.0.0.0/1",
                    "::/1",
                    "8000::/1"
                ]),
                all4: true,
                all6: true,
            }
        );
        let split = plan_routes(&nets(&["192.168.10.0/24", "fd00::/64"]));
        assert_eq!(split.routes, nets(&["fd00::/64", "192.168.10.0/24"]));
        assert!(!split.all4 && !split.all6);
    }

    fn gateway(gw: &str) -> Via {
        Via::Gateway(gw.into())
    }

    #[test]
    fn endpoints_get_a_route_the_default_way_once() {
        let first = plan_endpoint_routes(
            &EndpointRoutes::default(),
            &gateway("192.168.2.1"),
            &Via::Nowhere,
            &ips(&["198.51.100.7", "2001:db8::7"]),
            true,
            false,
        );
        // Only the family the tunnel takes whole needs one.
        assert!(first.delete.is_empty());
        assert_eq!(
            first.add,
            vec![(ips(&["198.51.100.7"])[0], gateway("192.168.2.1"))]
        );
        assert_eq!(first.next.routed, ips(&["198.51.100.7"]));

        let again = plan_endpoint_routes(
            &first.next,
            &gateway("192.168.2.1"),
            &Via::Nowhere,
            &ips(&["198.51.100.7"]),
            true,
            false,
        );
        assert!(again.delete.is_empty() && again.add.is_empty());
        assert_eq!(again.next, first.next);
    }

    #[test]
    fn a_new_network_moves_the_endpoint_routes() {
        let current = EndpointRoutes {
            via4: Some(gateway("192.168.2.1")),
            via6: Some(Via::Nowhere),
            routed: ips(&["198.51.100.7"]),
        };
        let moved = plan_endpoint_routes(
            &current,
            &gateway("10.0.0.1"),
            &Via::Nowhere,
            &ips(&["198.51.100.7"]),
            true,
            false,
        );
        assert_eq!(moved.delete, ips(&["198.51.100.7"]));
        assert_eq!(
            moved.add,
            vec![(ips(&["198.51.100.7"])[0], gateway("10.0.0.1"))]
        );

        // Offline: the endpoint is dropped rather than sent into the tunnel.
        let offline = plan_endpoint_routes(
            &current,
            &Via::Nowhere,
            &Via::Nowhere,
            &ips(&["198.51.100.7"]),
            true,
            false,
        );
        assert_eq!(offline.add, vec![(ips(&["198.51.100.7"])[0], Via::Nowhere)]);
    }

    #[test]
    fn an_endpoint_that_moved_loses_its_old_route() {
        let current = EndpointRoutes {
            via4: Some(gateway("192.168.2.1")),
            via6: Some(Via::Nowhere),
            routed: ips(&["198.51.100.7"]),
        };
        let roamed = plan_endpoint_routes(
            &current,
            &gateway("192.168.2.1"),
            &Via::Nowhere,
            &ips(&["203.0.113.9"]),
            true,
            false,
        );
        assert_eq!(roamed.delete, ips(&["198.51.100.7"]));
        assert_eq!(
            roamed.add,
            vec![(ips(&["203.0.113.9"])[0], gateway("192.168.2.1"))]
        );
        assert_eq!(roamed.next.routed, ips(&["203.0.113.9"]));
    }

    /// A tunnel up and down for real, split so the Mac keeps its own
    /// default route. It needs root and the installed VPN runtime, so run
    /// the test binary with sudo rather than cargo, which would leave
    /// root's files in target/:
    ///
    /// ```text
    /// cargo test -p supermanager-helper --no-run   # prints the binary
    /// sudo target/debug/deps/supermanager_helper-<hash> --ignored native_tunnel
    /// ```
    #[tokio::test]
    #[ignore = "needs root and the installed VPN runtime, see the doc comment"]
    async fn a_native_tunnel_comes_up_and_goes_down() {
        use base64::Engine as _;
        let key = |byte: u8| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
        let name = "smwgtest0001";
        let config = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.213.0.2/24\n\
             [Peer]\nPublicKey = {}\nEndpoint = 192.0.2.1:51820\n\
             AllowedIPs = 10.213.1.0/24\nPersistentKeepalive = 25\n",
            key(1),
            key(2)
        );
        let (interface, tunnel) = up(name, &config).await.unwrap();
        assert!(net::exists(&interface));
        assert_eq!(read_name_file(name).as_deref(), Some(interface.as_str()));
        assert!(net::routed_via(&"10.213.1.0/24".parse().unwrap(), &interface).await);
        assert_eq!(
            uapi::endpoints(&interface).await.unwrap(),
            ips(&["192.0.2.1"])
        );
        down(name, Some(tunnel)).await.unwrap();
        assert!(!net::exists(&interface));
        assert!(!exists(name));
        assert!(read_name_file(name).is_none());
    }

    #[test]
    fn state_survives_the_helper() {
        let state = State {
            name: "smwg0a1b2c3d".into(),
            interface: "utun7".into(),
            pid: 4242,
            mtu: None,
            all4: true,
            all6: false,
            endpoint_routes: EndpointRoutes {
                via4: Some(gateway("fe80::1%en0")),
                via6: Some(Via::Interface("utun5".into())),
                routed: ips(&["198.51.100.7"]),
            },
        };
        let json = serde_json::to_vec(&state).unwrap();
        assert_eq!(serde_json::from_slice::<State>(&json).unwrap(), state);
    }
}
