use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: uplc-encoder <input.uplc> <output.flat>");
        process::exit(2);
    }
    let source = fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("failed to read {}: {e}", args[1]);
        process::exit(2);
    });
    let program = uplc::parser::program(&source).unwrap_or_else(|e| {
        eprintln!("parse error: {e}");
        process::exit(1);
    });
    let flat = program.to_flat().unwrap_or_else(|e| {
        eprintln!("encode error: {e}");
        process::exit(1);
    });
    fs::write(&args[2], flat).unwrap_or_else(|e| {
        eprintln!("failed to write {}: {e}", args[2]);
        process::exit(2);
    });
}
