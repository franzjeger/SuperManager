//! Unprivileged identity integration fixture. No RPC dispatch or networking actions.
#[allow(dead_code)]
#[path = "../src/authorization.rs"]
mod authorization;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("socket path required"))?;
    let listener = tokio::net::UnixListener::bind(path)?;
    let (stream, _) =
        tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept()).await??;
    authorization::authorize(&stream)?;
    use tokio::io::AsyncWriteExt;
    let mut stream = stream;
    stream.write_all(b"authorized\n").await?;
    Ok(())
}
