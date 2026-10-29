# zkVM Tools

| Tool | Purpose |
|------|---------|
| [`artifact-gen/`](artifact-gen/) | Generate flat artifacts from Aiken projects via `aiken export` |

## Usage

### artifact-gen

```bash
cd zkVM/tools/artifact-gen
cargo build --release

# Generate a flat artifact
./target/release/aiken-artifact-gen \
  --project ../../aiken/vrf \
  --module vrf/core \
  --name verify \
  --output /tmp/vrf_verify.flat
```

Or use as a library:
```rust
use aiken_artifact_gen::{ArtifactGenerator, GeneratorConfig};
let config = GeneratorConfig {
    project_dir: "../../aiken/vrf".to_string(),
    module: "vrf/core".to_string(),
    name: "verify".to_string(),
    output_path: "/tmp/vrf_verify.flat".to_string(),
};
ArtifactGenerator::new(config).generate()?;
```
