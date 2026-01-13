# argon2-cli

Generate Argon2 hashes from command line

## Installation

```bash
cargo install --path .
```

## Usage

```bash
echo -n "password" | argon2 somesalt
```

### Options

```
argon2 [-h] salt [-i|-d|-id] [-t iterations] [-m log2(memory in KiB) | -k memory in KiB] [-p parallelism] [-l hash length] [-e|-r] [-v (10|13)]
```

- `-i` Use Argon2i (default)
- `-d` Use Argon2d
- `-id` Use Argon2id
- `-t` Number of iterations (default: 3)
- `-m` Memory usage of 2^N KiB (default: 12)
- `-k` Memory usage of N KiB (default: 4096)
- `-p` Parallelism threads (default: 1)
- `-l` Hash output length in bytes (default: 32)
- `-e` Output only encoded hash
- `-r` Output only raw bytes
- `-v` Argon2 version (default: 13)

## Examples

```bash
# Basic usage
echo -n "password" | argon2 somesalt

# Use Argon2id with custom parameters
echo -n "password" | argon2 somesalt -id -t 4 -m 16 -p 4

# Output only encoded hash
echo -n "password" | argon2 somesalt -e
```

## License

MIT
