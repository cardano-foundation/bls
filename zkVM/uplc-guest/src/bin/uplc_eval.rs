use std::{env, fs, process};

use uplc_guest::{eval_flat, hex_decode, Data};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: uplc-eval <program.flat> [--data-bytes HEX]...");
        process::exit(2);
    }

    let flat = fs::read(&args[1]).unwrap_or_else(|error| {
        eprintln!("failed to read {}: {error}", args[1]);
        process::exit(2);
    });

    let mut data_args = Vec::new();
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--data-bytes" => {
                let value = args.get(index + 1).unwrap_or_else(|| {
                    eprintln!("--data-bytes requires a hex value");
                    process::exit(2);
                });
                let bytes = hex_decode(value).unwrap_or_else(|| {
                    eprintln!("invalid hex value: {value}");
                    process::exit(2);
                });
                data_args.push(Data::B(bytes));
                index += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                process::exit(2);
            }
        }
    }

    match eval_flat(&flat, &data_args) {
        Ok(value) => {
            if let Some(hex) = value.to_hex_string() {
                println!("{hex}");
            } else {
                println!("{}", value.describe());
            }
        }
        Err(error) => {
            eprintln!("evaluation failed: {error}");
            process::exit(1);
        }
    }
}
