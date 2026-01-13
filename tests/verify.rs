use std::process::Command;
use std::io::Write;
use rand::Rng;
use std::collections::HashMap;

const REF_BINARY: &str = "argon2";
// We assume the binary is at the standard release location relative to the test runner.
const RUST_BINARY: &str = "./target/release/argon2-cli";

fn generate_random_string(len: usize) -> String {
    let mut rng = rand::rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn run_argon2(binary: &str, salt: &str, password: &str, args: &[String]) -> Result<String, String> {
    let mut cmd = Command::new(binary);
    cmd.arg(salt);
    for arg in args {
        cmd.arg(arg);
    }
    
    // Setup stdin
    cmd.stdin(std::process::Stdio::piped())
       .stdout(std::process::Stdio::piped())
       .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn {}: {}", binary, e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes()).map_err(|e| format!("Failed to write to stdin: {}", e))?;
    }

    let output = child.wait_with_output().map_err(|e| format!("Failed to wait: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_output(output: &str) -> HashMap<String, String> {
    let mut data = HashMap::new();
    for line in output.lines() {
        if let Some((key, val)) = line.split_once(':') {
            data.insert(key.trim().to_string(), val.trim().to_string());
        }
    }
    data
}

fn verify(i: u32, memory_exp: u32, parallelism: u32, variant: &str) -> bool {
    let salt = generate_random_string(8);
    let password = generate_random_string(12);

    let mut args = Vec::new();
    if !variant.is_empty() {
        args.push(format!("-{}", variant));
    }
    args.push("-t".to_string());
    args.push(i.to_string());
    args.push("-m".to_string());
    args.push(memory_exp.to_string());
    args.push("-p".to_string());
    args.push(parallelism.to_string());

    let ref_out = match run_argon2(REF_BINARY, &salt, &password, &args) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("Reference binary error: {}", e);
            return false;
        }
    };

    let rust_out = match run_argon2(RUST_BINARY, &salt, &password, &args) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("Rust binary error: {}", e);
            return false;
        }
    };

    let ref_data = parse_output(&ref_out);
    let rust_data = parse_output(&rust_out);

    let keys_to_check = ["Iterations", "Memory", "Parallelism", "Hash", "Encoded"];
    
    let mut success = true;
    for key in keys_to_check {
        let ref_val = ref_data.get(key);
        let rust_val = rust_data.get(key);
        
        if ref_val.is_none() { continue; } // e/-r flags not processed here yet
        
        if rust_val.is_none() {
            eprintln!("Mismatch: key '{}' missing in Rust output", key);
            success = false;
            continue;
        }

        if ref_val != rust_val {
            eprintln!("Mismatch for '{}':\n  Ref:  {:?}\n  Rust: {:?}", key, ref_val, rust_val);
            success = false;
        }
    }
    
    if success {
        println!("OK");
    }
    success
}

#[test]
fn test_argon2_compatibility() {
    // Build release binary first
    let status = Command::new("cargo")
        .args(&["build", "--release", "--bin", "argon2-cli"])
        .status()
        .expect("Failed to build binary");
    assert!(status.success(), "Construction of binary failed");

    // Basic Test
    assert!(verify(3, 12, 1, "i"), "Basic test failed");

    let mut rng = rand::rng();
    let variants = ["i", "d", "id"];

    for _ in 0..20 {
        let iterations = rng.random_range(1..=5);
        let parallelism = rng.random_range(1..=4);
        // Ensure valid memory: 2^m >= 8 * p
        let memory_exp = rng.random_range(6..=12);
        let var_idx = rng.random_range(0..variants.len());
        let variant = variants[var_idx];

        if !verify(iterations, memory_exp, parallelism, variant) {
            panic!("Random test failed with: t={}, m={}, p={}, var={}", iterations, memory_exp, parallelism, variant);
        }
    }
}
