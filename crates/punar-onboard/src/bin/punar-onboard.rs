#![forbid(unsafe_code)]

use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use punar_onboard::protocol::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(
    name = "punar-onboard",
    about = "Submit the local first-account transaction over stdin"
)]
struct Cli {
    #[arg(long, default_value = "/run/punar-onboardd/onboard.sock", hide = true)]
    socket: PathBuf,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            let _ = writeln!(
                io::stdout(),
                "{{\"v\":1,\"ok\":false,\"code\":\"service_unavailable\",\"field\":null,\"message\":\"Account creation is unavailable. Nothing was changed; restart and try again.\",\"changed\":false}}"
            );
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), ()> {
    let mut input = Zeroizing::new(Vec::with_capacity(512));
    io::stdin()
        .lock()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut input)
        .map_err(|_| ())?;
    if input.last() == Some(&b'\n') {
        input.pop();
    }
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES {
        input.zeroize();
        return Err(());
    }

    let mut stream = UnixStream::connect(cli.socket).map_err(|_| ())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(45)))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ())?;
    let len: u32 = input.len().try_into().map_err(|_| ())?;
    stream.write_all(&len.to_le_bytes()).map_err(|_| ())?;
    stream.write_all(&input).map_err(|_| ())?;
    stream.flush().map_err(|_| ())?;
    input.zeroize();

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(|_| ())?;
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_RESPONSE_BYTES {
        return Err(());
    }
    let mut response = Zeroizing::new(vec![0_u8; len]);
    stream.read_exact(&mut response).map_err(|_| ())?;
    io::stdout().write_all(&response).map_err(|_| ())?;
    io::stdout().write_all(b"\n").map_err(|_| ())?;
    io::stdout().flush().map_err(|_| ())?;
    response.zeroize();
    Ok(())
}
