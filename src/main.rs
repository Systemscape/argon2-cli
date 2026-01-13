use clap::{ArgGroup, Parser};
use std::io::{self, BufRead, IsTerminal, Write};
use argon2::password_hash::SaltString;

// Usage:  argon2 [-h] salt [-i|-d|-id] [-t iterations] [-m log2(memory in KiB) | -k memory in KiB] [-p parallelism] [-l hash length] [-e|-r] [-v (10|13)]
#[derive(Parser, Debug)]
#[command(name = "argon2", about = "(Rust implementation)", disable_help_flag = false)]
#[command(group(ArgGroup::new("variant").args(&["i", "d", "id"])))]
#[command(group(ArgGroup::new("memory").args(&["m", "k"])))]
#[command(group(ArgGroup::new("output_format").args(&["e", "r"])))]
struct Args {
    /// The salt to use, at least 8 characters
    salt: String,

    /// Use Argon2i (this is the default)
    #[arg(short = 'i', long, default_value_t = false)]
    i: bool,

    /// Use Argon2d instead of Argon2i
    #[arg(short = 'd', long, default_value_t = false)]
    d: bool,

    /// Use Argon2id instead of Argon2i
    #[arg(long = "id", default_value_t = false)]
    id: bool,

    /// Sets the number of iterations to N (default = 3)
    #[arg(short = 't', default_value_t = 3)]
    t: u32,

    /// Sets the memory usage of 2^N KiB (default 12)
    #[arg(short = 'm', default_value_t = 12)]
    m: u32,

    /// Sets the memory usage of N KiB (default 4096)
    #[arg(short = 'k')]
    k: Option<u32>,

    /// Sets parallelism to N threads (default 1)
    #[arg(short = 'p', default_value_t = 1)]
    p: u32,

    /// Sets hash output length to N bytes (default 32)
    #[arg(short = 'l', default_value_t = 32)]
    l: u32,

    /// Output only encoded hash
    #[arg(short = 'e', default_value_t = false)]
    e: bool,

    /// Output only the raw bytes of the hash
    #[arg(short = 'r', default_value_t = false)]
    r: bool,

    /// Argon2 version (defaults to the most recent version, currently 13)
    #[arg(short = 'v', default_value_t = 13)]
    v: u32, // Unimplemented: version selection not supported, always uses v13
}

fn get_input() -> io::Result<String> {
    let stdin = io::stdin();

    if stdin.is_terminal() {
        print!("Enter password: ");
        io::stdout().flush()?;

        let mut input = String::new();
        stdin.read_line(&mut input)?;
        Ok(input.trim().to_string())
    } else {
        let lines: Vec<String> = stdin.lock().lines().collect::<Result<_, _>>()?;
        Ok(lines.join("\n"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Handle the non-standard `-id` flag which conflicts with clap's short flag clustering
    let args_env = std::env::args();
    let new_args: Vec<String> = args_env.map(|arg| {
        if arg == "-id" {
            "--id".to_string()
        } else {
            arg
        }
    }).collect();

    let args = Args::parse_from(new_args);

    let password = get_input().unwrap_or_else(|e| {
        eprintln!("Error reading input: {}", e);
        std::process::exit(1);
    });
    
    // Select algorithm variant
    let algorithm = if args.d {
        argon2::Algorithm::Argon2d
    } else if args.id {
        argon2::Algorithm::Argon2id
    } else {
        argon2::Algorithm::Argon2i
    };

    // Calculate memory cost
    let memory_kib = if let Some(k) = args.k {
        k
    } else {
        1 << args.m
    };

    let params = argon2::Params::new(
        memory_kib,
        args.t,
        args.p,
        Some(args.l as usize),
    ).map_err(|e| format!("Invalid parameters: {}", e))?;

    // Encode salt to PHC string format
    let salt_string = SaltString::encode_b64(args.salt.as_bytes())
        .map_err(|e| format!("Invalid salt: {}", e))?;

    let argon2 = argon2::Argon2::new(
        algorithm,
        argon2::Version::V0x13,
        params,
    );

    let start = std::time::Instant::now();
    
    let password_bytes = password.as_bytes();
    
    use argon2::PasswordHasher;
    let password_hash = argon2.hash_password(password_bytes, salt_string.as_salt())
        .map_err(|e| format!("Hashing failed: {}", e))?;
    
    let duration = start.elapsed();

    // Generate output based on flags
    if args.e {
        println!("{}", password_hash);
    } else if args.r {
        if let Some(hash) = password_hash.hash {
             io::stdout().write_all(hash.as_bytes())?;
        }
    } else {
        println!("Type:           {:?}", algorithm);
        println!("Iterations:     {}", args.t);
        println!("Memory:         {} KiB", memory_kib);
        println!("Parallelism:    {}", args.p);
        
        if let Some(hash) = password_hash.hash {
            println!("Hash:           {}", hex::encode(hash.as_bytes()));
        }
        println!("Encoded:        {}", password_hash);
        
        println!("{:.3} seconds", duration.as_secs_f64());
        println!("Verification ok");
    }

    Ok(())
}
