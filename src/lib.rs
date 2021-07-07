use async_std::prelude::*;
use async_std::fs;
use async_std::io::{BufReader, BufWriter, Error, ErrorKind, Result, copy};
use async_std::net::{IpAddr,TcpListener, TcpStream};
use async_std::task::spawn;
use std::str;
use regex::Regex;

pub async fn start_server(port: u16, filename: &str) -> Result<()> {
    let (res1, res2) = fs::read_to_string(filename)
        .join(TcpListener::bind(format!("0.0.0.0:{}", port)))
        .await;

    let (contents, listener) = (res1?, res2?);

    let patterns = contents
        .split("\n")
        .map(|str| str.trim())
        .filter(|str| !str.is_empty())
        .map(|str| Regex::new(str).unwrap())
        .collect::<Vec<Regex>>();

    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
       spawn(handle_connection(stream?, patterns.clone()));
    }

    Ok(())
}

async fn handle_connection(src_stream: TcpStream, patterns: Vec<Regex>) {
    match _handle_connection(src_stream, patterns).await {
        Ok(()) => {},

        Err(err) => {
            let err_str = err.to_string();

            if err_str.starts_with("[v") {
                println!("{}", err_str);
            } else {
                eprintln!("{}", err);
            }
        }
    }
}

async fn _handle_connection(mut src_stream: TcpStream, patterns: Vec<Regex>) -> Result<()> {
    let mut reader = BufReader::new(&src_stream);
    let writer = BufWriter::new(&src_stream);

    let mut buf: [u8; 1024] = [0; 1024];
    let n = reader.read(&mut buf).await?;

    if n == 0 {
        let err = Error::new(ErrorKind::Other, "Reached EOF");

        return Err(err);
    }

    let mut dst_stream: TcpStream;

    match buf[0] {
        4 => {
            dst_stream = handle_socks4(reader, writer, &mut buf, n, patterns).await?;
        },

        5 => {
            dst_stream = handle_socks5(reader, writer, &mut buf, n, patterns).await?;
        },

        _ => {
            let msg = format!("Unexpected SOCKS version: {}", buf[0]);
            let err = Error::new(ErrorKind::Other, msg);

            return Err(err);
        }
    }

    let mut src_stream2 = src_stream.clone();
    let mut dst_stream2 = dst_stream.clone();

    let (res1, res2) = copy(&mut src_stream, &mut dst_stream)
        .join(copy(&mut dst_stream2, &mut src_stream2)).await;

    (res1?, res2?);

    Ok(())
}

async fn handle_socks4(mut reader: BufReader<&TcpStream>, mut writer: BufWriter<&TcpStream>, buf: &mut [u8], mut n: usize, patterns: Vec<Regex>) -> Result<TcpStream> {
    while n < 8 {
        n += reader.read(&mut buf[n..]).await?;
    }

    let mut resp: [u8; 8] = [0, 0x5A, 0, 0, 0, 0, 0, 0];

    match buf[1] {
        1 => {

        },

        2 => {
            resp[1] = 0x5B;
            writer.write_all(&mut resp).await?;
            writer.flush().await?;

            let err = Error::new(ErrorKind::Other, "handle_socks4(): Port binding not supported");

            return Err(err);
        },

        _ => {
            resp[1] = 0x5B;
            writer.write_all(&mut resp).await?;
            writer.flush().await?;

            let err = Error::new(ErrorKind::Other, format!("handle_socks4(): Unexpected command: {:#04x}", buf[1]));

            return Err(err);
        }
    }

    let dst_port = (buf[2] as u16) * 256 + (buf[3] as u16);

    let mut dst_host = if buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0 {
        String::new()
    } else {
        let mut arr: [u8; 4] = [0; 4];

        for (i, oct) in buf[4..8].iter().enumerate() {
            arr[i] = *oct;
        }

        IpAddr::from(arr).to_string()
    };

    let mut vec = &mut buf[n..].to_vec();
    let x = reader.read_until(0, &mut vec).await?;

    let user_id = if x > 1 {
        str::from_utf8(&vec[..x-1])
            .map_err(|err| Error::new(ErrorKind::Other, err))?
            .to_string()
    } else {
        String::new()
    };

    if dst_host.is_empty() {
        let x = reader.read_until(0, &mut vec).await?;

        if x > 1 {
            dst_host = str::from_utf8(&vec[..x-1])
                .map_err(|err| Error::new(ErrorKind::Other, err))?
                .to_string();
        }
    }

    if dst_host.is_empty() {
        resp[1] = 0x5B;
        writer.write_all(&mut resp).await?;
        writer.flush().await?;

        let err = Error::new(ErrorKind::Other, "handle_socks4(): No valid host specified");

        return Err(err);
    }

     match patterns.iter().find(|pattern| pattern.is_match(&dst_host)) {
        Some(_) => {
            resp[1] = 0x5B;
            writer.write_all(&mut resp).await?;
            writer.flush().await?;

            let err = Error::new(ErrorKind::Other, format!("[v4] Host blocked: {}", dst_host));

            return Err(err);
        },

        _ => {}
    }

    let stream = TcpStream::connect(format!("{}:{}", dst_host, dst_port)).await?;

    writer.write_all(&mut resp).await?;
    writer.flush().await?;

    if user_id.is_empty() {
        println!("[v4] {}:{}", dst_host, dst_port);
    } else {
        println!("[v4] {}@{}:{}", user_id, dst_host, dst_port);
    }

    Ok(stream)
}

async fn handle_socks5(mut reader: BufReader<&TcpStream>, mut writer: BufWriter<&TcpStream>, buf: &mut [u8], mut n: usize, patterns: Vec<Regex>) -> Result<TcpStream> {
    while n < 2 && n < buf[1] as usize {
        n += reader.read(&mut buf[n..]).await?;
    }

    let nauth = buf[1] as usize;
    let nreq = 2 + nauth;
    let naddr = nreq + 4;

    let mut greeting: [u8; 2] = [5, 0];

    if buf[2..nreq].contains(&0) {
        writer.write_all(&mut greeting).await?;
        writer.flush().await?;
    } else {
        greeting[1] = 0xFF;
        writer.write_all(&mut greeting).await?;
        writer.flush().await?;

        let err = Error::new(ErrorKind::Other, "handle_socks5(): No supported authentication method");

        return Err(err);
    }

    while n < naddr {
        n += reader.read(&mut buf[n..]).await?;
    }

    let mut resp: [u8; 22] = [0; 22];

    resp[0] = 5;
    resp[3] = 1;

    if buf[nreq] != 5 {
        resp[1] = 1;
        writer.write_all(&mut resp[..10]).await?;
        writer.flush().await?;

        let err = Error::new(ErrorKind::Other, "handle_socks5(): Expected SOCKSv5");

        return Err(err);
    }

    if buf[nreq+1] != 1 {
        resp[1] = 1;
        writer.write_all(&mut resp[..10]).await?;
        writer.flush().await?;

        let err = Error::new(ErrorKind::Other, format!("handle_socks5(): Unsupported command: {}", buf[nreq+1]));

        return Err(err);
    }

    if buf[nreq+2] != 0 {
        resp[1] = 1;
        writer.write_all(&mut resp[..10]).await?;
        writer.flush().await?;

        let err = Error::new(ErrorKind::Other, "handle_socks5(): Expected reserved (null) byte");

        return Err(err);
    }

    let dst_host = match buf[nreq+3] {
        1 => {
            while n < naddr + 4 + 2 {
                n += reader.read(&mut buf[n..]).await?;
            }

            let mut arr: [u8; 4] = [0; 4];

            for (i, oct) in buf[naddr..naddr+4].iter().enumerate() {
                arr[i] = *oct;
            }

            Ok(IpAddr::from(arr).to_string())
        },

        3 => {
            while buf[naddr] == 0 && n < naddr + 1 + buf[naddr] as usize + 2 {
                n += reader.read(&mut buf[n..]).await?;
            }

            Ok(
                str::from_utf8(&buf[naddr+1..naddr+1+buf[naddr] as usize])
                    .map_err(|err| Error::new(ErrorKind::Other, err))?
                    .to_string()
            )
        },

        4 => {
            while buf[naddr] == 0 && n < naddr + 16 + 2 {
                n += reader.read(&mut buf[n..]).await?;
            }

            let mut arr: [u8; 16] = [0; 16];

            for (i, oct) in buf[naddr..naddr+16].iter().enumerate() {
                arr[i] = *oct;
            }

            Ok(IpAddr::from(arr).to_string())
        },

        _ => {
            resp[1] = 1;
            writer.write_all(&mut resp[..10]).await?;
            writer.flush().await?;

            let err = Error::new(ErrorKind::Other, format!("handle_socks5(): Unrecognized address type: {:#04x}", buf[nreq+3]));

            Err(err)
        }
    }?;

    match patterns.iter().find(|pattern| pattern.is_match(&dst_host)) {
        Some(_) => {
            resp[1] = 2;
            writer.write_all(&mut resp[..10]).await?;
            writer.flush().await?;

            let err = Error::new(ErrorKind::Other, format!("[v5] Host blocked: {}", dst_host));

            return Err(err);
        },

        _ => {}
    }

    let dst_port = (buf[n-2] as u16) * 256 + (buf[n-1] as u16);
    let stream = TcpStream::connect(format!("{}:{}", dst_host, dst_port)).await?;

    let src_addr = stream.local_addr()?;
    let src_port = src_addr.port();

    match src_addr.ip() {
        IpAddr::V4(ip) => {
            resp[3] = 1;

            for (i, oct) in ip.octets().iter().enumerate() {
                resp[4+i] = *oct;
            }

            resp[8] = (src_port % 256) as u8;
            resp[9] = ((src_port / 256) % 256) as u8;

            writer.write_all(&mut resp[..10]).await?;
            writer.flush().await?;
        },

        IpAddr::V6(ip) => {
            resp[3] = 4;

            for (i, oct) in ip.octets().iter().enumerate() {
                resp[4+i] = *oct;
            }

            resp[20] = (src_port % 256) as u8;
            resp[21] = ((src_port / 256) % 256) as u8;

            writer.write_all(&mut resp[..22]).await?;
            writer.flush().await?;
        }
    }

    println!("[v5] {}:{}", dst_host, dst_port);

    Ok(stream)
}
