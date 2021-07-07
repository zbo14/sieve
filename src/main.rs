use async_std::io::{Result};
use sieve::{start_server};

#[async_std::main]
async fn main() -> Result<()> {
    start_server(9050, "patterns.txt").await
}
