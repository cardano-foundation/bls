use clap::Parser;
use aiken_artifact_gen::{ArtifactGenerator, GeneratorConfig};
use std::process;

#[derive(Parser, Debug)]
#[command(name = "aiken-artifact-gen")]
#[command(about = "Generate flat artifacts from Aiken projects")]
struct Args {
    #[arg(short, long)]
    project: String,
    #[arg(short, long)]
    module: String,
    #[arg(short, long)]
    name: String,
    #[arg(short, long)]
    output: String,
}

fn main() {
    let args = Args::parse();
    let config = GeneratorConfig {
        project_dir: args.project,
        module: args.module,
        name: args.name,
        output_path: args.output,
    };
    let gen = ArtifactGenerator::new(config);
    if let Err(e) = gen.generate() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
    println!("artifact generated");
}
