#!/usr/bin/env python3
"""
gen_smt_input.py

Generate circuit witness input for CardanoKeyOwnershipSMT from a Cardano
address derived via cardano-addresses (https://github.com/IntersectMBO/cardano-addresses).

Workflow:
  1. cardano-address recovery-phrase generate --size 15 > phrase.prv
  2. cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
  3. cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
  4. cardano-address key public --without-chain-code < pay.xsk > pay.vk
  5. python3 gen_smt_input.py --xsk pay.xsk --vk pay.vk -o input.json

The script:
  1. Decodes the bech32 extended signing key and public key
  2. Extracts the Ed25519 scalar and public key
  3. Decompresses the point
  4. Computes the MiMC leaf = MultiMiMC7(x_chunks, y_chunks) over the 85-bit
     chunks of both coordinates (matching the circuit's leaf commitment)
  5. Builds the zero-padded Merkle tree of the given depth with the leaf at
     the given index via the `groth16-prover smt` CLI (`smt insert --index`,
     `smt path --json`, `smt verify`) — with an equivalent in-Python builder
     as fallback when the CLI is not available
  6. Generates the Merkle proof (siblings and directions)
  7. Emits the JSON input expected by the CardanoKeyOwnershipSMT circuit

Usage:
  python3 gen_smt_input.py --xsk pay.xsk --vk pay.vk -o input.json [--depth 4] [--index 0] [--smt-cli groth16-prover]
"""

import argparse
import json
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile


# Ed25519 field prime (used for public key decompression)
P_ED = 2**255 - 19

# BLS12-381 SCALAR field prime (the field circom uses with --prime bls12381;
# this is where all MiMC arithmetic must be performed)
P_BLS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# MiMC(x^7) round constants for the BLS12-381 scalar field (same as in
# groth16-prover/src/mimc.rs and circom/Privacy/mimc.circom)
ROUND_CONSTANTS = [
    0,
    20888961410941983456478427210666206549300505294776164667214940546594746570981,
    15265126113435022738560151911929040668591755459209400716467504685752745317193,
    8334177627492981984476504167502758309043212251641796197711684499645635709656,
    1374324219480165500871639364801692115397519265181803854177629327624133579404,
    11442588683664344394633565859260176446561886575962616332903193988751292992472,
    2558901189096558760448896669327086721003508630712968559048179091037845349145,
    11189978595292752354820141775598510151189959177917284797737745690127318076389,
    3262966573163560839685415914157855077211340576201936620532175028036746741754,
    17029914891543225301403832095880481731551830725367286980611178737703889171730,
    4614037031668406927330683909387957156531244689520944789503628527855167665518,
    19647356996769918391113967168615123299113119185942498194367262335168397100658,
    5040699236106090655289931820723926657076483236860546282406111821875672148900,
    2632385916954580941368956176626336146806721642583847728103570779270161510514,
    17691411851977575435597871505860208507285462834710151833948561098560743654671,
    11482807709115676646560379017491661435505951727793345550942389701970904563183,
    8360838254132998143349158726141014535383109403565779450210746881879715734773,
    12663821244032248511491386323242575231591777785787269938928497649288048289525,
    3067001377342968891237590775929219083706800062321980129409398033259904188058,
    8536471869378957766675292398190944925664113548202769136103887479787957959589,
    19825444354178182240559170937204690272111734703605805530888940813160705385792,
    16703465144013840124940690347975638755097486902749048533167980887413919317592,
    13061236261277650370863439564453267964462486225679643020432589226741411380501,
    10864774797625152707517901967943775867717907803542223029967000416969007792571,
    10035653564014594269791753415727486340557376923045841607746250017541686319774,
    3446968588058668564420958894889124905706353937375068998436129414772610003289,
    4653317306466493184743870159523234588955994456998076243468148492375236846006,
    8486711143589723036499933521576871883500223198263343024003617825616410932026,
    250710584458582618659378487568129931785810765264752039738223488321597070280,
    2104159799604932521291371026105311735948154964200596636974609406977292675173,
    16313562605837709339799839901240652934758303521543693857533755376563489378839,
    6032365105133504724925793806318578936233045029919447519826248813478479197288,
    14025118133847866722315446277964222215118620050302054655768867040006542798474,
    7400123822125662712777833064081316757896757785777291653271747396958201309118,
    1744432620323851751204287974553233986555641872755053103823939564833813704825,
    8316378125659383262515151597439205374263247719876250938893842106722210729522,
    6739722627047123650704294650168547689199576889424317598327664349670094847386,
    21211457866117465531949733809706514799713333930924902519246949506964470524162,
    13718112532745211817410303291774369209520657938741992779396229864894885156527,
    5264534817993325015357427094323255342713527811596856940387954546330728068658,
    18884137497114307927425084003812022333609937761793387700010402412840002189451,
    5148596049900083984813839872929010525572543381981952060869301611018636120248,
    19799686398774806587970184652860783461860993790013219899147141137827718662674,
    19240878651604412704364448729659032944342952609050243268894572835672205984837,
    10546185249390392695582524554167530669949955276893453512788278945742408153192,
    5507959600969845538113649209272736011390582494851145043668969080335346810411,
    18177751737739153338153217698774510185696788019377850245260475034576050820091,
    19603444733183990109492724100282114612026332366576932662794133334264283907557,
    10548274686824425401349248282213580046351514091431715597441736281987273193140,
    1823201861560942974198127384034483127920205835821334101215923769688644479957,
    11867589662193422187545516240823411225342068709600734253659804646934346124945,
    18718569356736340558616379408444812528964066420519677106145092918482774343613,
    10530777752259630125564678480897857853807637120039176813174150229243735996839,
    20486583726592018813337145844457018474256372770211860618687961310422228379031,
    12690713110714036569415168795200156516217175005650145422920562694422306200486,
    17386427286863519095301372413760745749282643730629659997153085139065756667205,
    2216432659854733047132347621569505613620980842043977268828076165669557467682,
    6309765381643925252238633914530877025934201680691496500372265330505506717193,
    20806323192073945401862788605803131761175139076694468214027227878952047793390,
    4037040458505567977365391535756875199663510397600316887746139396052445718861,
    19948974083684238245321361840704327952464170097132407924861169241740046562673,
    845322671528508199439318170916419179535949348988022948153107378280175750024,
    16222384601744433420585982239113457177459602187868460608565289920306145389382,
    10232118865851112229330353999139005145127746617219324244541194256766741433339,
    6699067738555349409504843460654299019000594109597429103342076743347235369120,
    6220784880752427143725783746407285094967584864656399181815603544365010379208,
    6129250029437675212264306655559561251995722990149771051304736001195288083309,
    10773245783118750721454994239248013870822765715268323522295722350908043393604,
    4490242021765793917495398271905043433053432245571325177153467194570741607167,
    19596995117319480189066041930051006586888908165330319666010398892494684778526,
    837850695495734270707668553360118467905109360511302468085569220634750561083,
    11803922811376367215191737026157445294481406304781326649717082177394185903907,
    10201298324909697255105265958780781450978049256931478989759448189112393506592,
    13564695482314888817576351063608519127702411536552857463682060761575100923924,
    9262808208636973454201420823766139682381973240743541030659775288508921362724,
    173271062536305557219323722062711383294158572562695717740068656098441040230,
    18120430890549410286417591505529104700901943324772175772035648111937818237369,
    20484495168135072493552514219686101965206843697794133766912991150184337935627,
    19155651295705203459475805213866664350848604323501251939850063308319753686505,
    11971299749478202793661982361798418342615500543489781306376058267926437157297,
    18285310723116790056148596536349375622245669010373674803854111592441823052978,
    7069216248902547653615508023941692395371990416048967468982099270925308100727,
    6465151453746412132599596984628739550147379072443683076388208843341824127379,
    16143532858389170960690347742477978826830511669766530042104134302796355145785,
    19362583304414853660976404410208489566967618125972377176980367224623492419647,
    1702213613534733786921602839210290505213503664731919006932367875629005980493,
    10781825404476535814285389902565833897646945212027592373510689209734812292327,
    4212716923652881254737947578600828255798948993302968210248673545442808456151,
    7594017890037021425366623750593200398174488805473151513558919864633711506220,
    18979889247746272055963929241596362599320706910852082477600815822482192194401,
    13602139229813231349386885113156901793661719180900395818909719758150455500533,
]


def decode_bech32_file(path):
    with open(path, "r") as f:
        encoded = f.read().strip()
    try:
        result = subprocess.run(
            ["bech32"],
            input=encoded,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"bech32 CLI failed for {path}: {e.stderr}") from e
    except FileNotFoundError:
        print(
            "ERROR: 'bech32' CLI not found in PATH.\n"
            "  Install from https://github.com/IntersectMBO/bech32/releases\n"
            "  or build from source: cabal install bech32"
        )
        sys.exit(1)
    hex_str = result.stdout.strip()
    raw = bytes.fromhex(hex_str)
    hrp = encoded.split("1")[0] if "1" in encoded else ""
    return raw, hrp


def clamp_ed25519_scalar(kL):
    a = bytearray(kL[:32])
    a[0] &= 0xF8
    a[31] &= 0x7F
    a[31] |= 0x40
    return bytes(a)


def bytes_to_bits_le(data):
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def decompress_point(y_bytes):
    """Decompress an Ed25519 public key to extended coordinates [X, Y, Z, T]
    as integers modulo the Ed25519 field prime 2^255 - 19."""
    y_int = int.from_bytes(y_bytes, "little")
    sign_x = y_int >> 255
    y_int &= (1 << 255) - 1

    # Curve constant d = -121665 / 121666  (mod 2^255 - 19)
    d = -121665 * pow(121666, P_ED - 2, P_ED) % P_ED

    y2 = (y_int * y_int) % P_ED
    u = (y2 - 1) % P_ED
    v = (d * y2 + 1) % P_ED
    v_inv = pow(v, P_ED - 2, P_ED)
    x2 = (u * v_inv) % P_ED

    x = pow(x2, (P_ED + 3) // 8, P_ED)
    if (x * x) % P_ED != x2:
        x = (x * pow(2, (P_ED - 1) // 4, P_ED)) % P_ED

    if x & 1 != sign_x:
        x = (-x) % P_ED

    return [x, y_int, 1, (x * y_int) % P_ED]


def to_chunks(val, bits=85, n=3):
    chunks = []
    for i in range(n):
        chunk = (val >> (i * bits)) & ((1 << bits) - 1)
        chunks.append(chunk)
    return chunks


def mimc7(x, k, round_constants):
    """MiMC(x^7) permutation over the BLS12-381 scalar field."""
    state = x
    for i in range(len(round_constants)):
        state = (state + k + round_constants[i]) % P_BLS
        state = pow(state, 7, P_BLS)
    state = (state + k) % P_BLS
    return state


def mimc2(x, y):
    """MiMC compression: H(x, y) = MiMC7(y, x) + x + y."""
    return (mimc7(y, x, ROUND_CONSTANTS) + x + y) % P_BLS


def multi_mimc7(inputs, init=0):
    """Multi-input MiMC hash (Merkle-Damgard/Miyaguchi-Preneel mode).

    Matches the `MultiMimc7` template in circom/Privacy/mimc.circom and
    `mimc_hash` in groth16-prover/src/mimc.rs: t starts at `init` and each
    input is compressed via `mimc2(t, input)`.
    """
    t = init
    for x in inputs:
        t = mimc2(t, x)
    return t


def build_merkle_tree(leaf_index, depth, all_leaves):
    """Build a Merkle tree and return the root and the proof for the given leaf.

    Empty leaves default to 0; empty subtrees hash up as `mimc2(default, default)`,
    matching the padding scheme of `SparseMerkleTree` in
    groth16-prover/src/sparse_merkle_tree.rs.
    """
    # Pad all_leaves to a power of 2 with the empty-leaf default (0)
    n = 1 << depth
    all_leaves = list(all_leaves)
    while len(all_leaves) < n:
        all_leaves.append(0)
    all_leaves = all_leaves[:n]
    tree = [all_leaves[:]]
    current = all_leaves[:]
    for level in range(depth):
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            parent = mimc2(left, right)
            next_level.append(parent)
        tree.append(next_level)
        current = next_level

    root = tree[depth][0]

    # Generate proof for leaf at index leaf_index
    proof = []
    directions = []
    idx = leaf_index
    for level in range(depth):
        sibling_idx = idx ^ 1
        if sibling_idx < len(tree[level]):
            sibling = tree[level][sibling_idx]
        else:
            sibling = tree[level][idx]
        proof.append(sibling)
        directions.append(idx & 1)
        idx >>= 1

    return root, proof, directions


def build_merkle_tree_cli(leaf, index, depth, smt_cli):
    """Build the zero-padded SMT via the `groth16-prover smt` CLI.

    This is the primary, supported path. Uses `smt insert --index` to place
    the single leaf at `index`, `smt path --json` for the proof, and
    `smt verify` as a self-check. Returns `(root, siblings, directions, used_cli)`.

    The in-Python `build_merkle_tree` is a **fallback only** (identical
    padding scheme). It is used solely when the CLI is unavailable or errors
    (e.g. binary not built with the `privacy` feature or not on PATH), and a
    `WARNING:` is always printed when that happens.
    """
    if smt_cli:
        tmp = tempfile.mkdtemp(prefix="smt_cli_")
        try:
            state = os.path.join(tmp, "smt.json")
            subprocess.run(
                [smt_cli, "smt", "insert", "--depth", str(depth),
                 "--items", str(leaf), "--index", str(index), "--state", state],
                check=True, capture_output=True, text=True,
            )
            out = subprocess.run(
                [smt_cli, "smt", "path", "--state", state, "--leaf", str(leaf), "--json"],
                check=True, capture_output=True, text=True,
            )
            data = json.loads(out.stdout)
            subprocess.run(
                [smt_cli, "smt", "verify", "--state", state, "--leaf", str(leaf)],
                check=True, capture_output=True, text=True,
            )
            return (
                str(data["digest"]),
                [str(s) for s in data["siblings"]],
                [str(d) for d in data["directions"]],
                True,
            )
        except FileNotFoundError as e:
            print(f"WARNING: smt CLI '{smt_cli}' not found ({e}); "
                  "falling back to the in-Python Merkle builder (fallback only)")
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"WARNING: smt CLI failed ({e}); "
                  "falling back to the in-Python Merkle builder (fallback only)")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # Fallback (not the intended path): equivalent zero-padded tree in Python.
    all_leaves = [0] * (1 << depth)
    all_leaves[index] = leaf
    root, siblings, directions = build_merkle_tree(index, depth, all_leaves)
    return str(root), [str(s) for s in siblings], [str(d) for d in directions], False


def main():
    parser = argparse.ArgumentParser(
        description="Generate CardanoKeyOwnershipSMT circuit input from cardano-address keys."
    )
    parser.add_argument("--xsk", required=True, help="Path to payment extended signing key (pay.xsk)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--vk", help="Path to payment public key without chain code (pay.vk, 32 bytes)")
    group.add_argument("--xvk", help="Path to payment extended public key with chain code (pay.xvk, 64 bytes)")
    parser.add_argument("-o", "--output", default="input.json", help="Output JSON file (default: input.json)")
    parser.add_argument("--depth", type=int, default=4, help="SMT depth (default: 4)")
    parser.add_argument("--index", type=int, default=0, help="Leaf index in the SMT (default: 0)")
    parser.add_argument(
        "--smt-cli",
        default="groth16-prover",
        help="Path to the 'groth16-prover' binary used to build the SMT "
             "(must expose the 'smt' subcommand, i.e. be built with the "
             "'privacy' feature). Default: 'groth16-prover' (looked up on PATH).",
    )
    args = parser.parse_args()

    xsk_bytes, xsk_hrp = decode_bech32_file(args.xsk)
    if not xsk_hrp.endswith("_xsk"):
        print(f"WARNING: xsk HRP is '{xsk_hrp}', expected something ending in '_xsk'")
    if len(xsk_bytes) != 96:
        print(f"WARNING: xsk length is {len(xsk_bytes)}, expected 96 bytes")

    if args.vk:
        vk_bytes, vk_hrp = decode_bech32_file(args.vk)
        if not vk_hrp.endswith("_vk"):
            print(f"WARNING: vk HRP is '{vk_hrp}', expected something ending in '_vk'")
        if len(vk_bytes) != 32:
            print(f"WARNING: vk length is {len(vk_bytes)}, expected 32 bytes")
        pk_bytes = vk_bytes
    else:
        xvk_bytes, xvk_hrp = decode_bech32_file(args.xvk)
        if not xvk_hrp.endswith("_xvk"):
            print(f"WARNING: xvk HRP is '{xvk_hrp}', expected something ending in '_xvk'")
        if len(xvk_bytes) != 64:
            print(f"WARNING: xvk length is {len(xvk_bytes)}, expected 64 bytes")
        pk_bytes = xvk_bytes[:32]

    kL = xsk_bytes[:32]
    scalar = clamp_ed25519_scalar(kL)

    A_bits = bytes_to_bits_le(pk_bytes)
    sk_bits = bytes_to_bits_le(scalar)[:255]

    PointA = decompress_point(pk_bytes)
    PointA_chunks = [to_chunks(c) for c in PointA]

    # Leaf commitment: hash the full (x, y) coordinates, 85-bit chunks in the
    # same order as the circuit's MultiMimc7(6, 91) template.
    leaf = multi_mimc7(PointA_chunks[0] + PointA_chunks[1])

    smt_root, siblings, directions, used_cli = build_merkle_tree_cli(leaf, args.index, args.depth, args.smt_cli)

    circuit_input = {
        "A": [str(b) for b in A_bits],
        "sk": [str(b) for b in sk_bits],
        "PointA": [[str(c) for c in row] for row in PointA_chunks],
        "smt_root": str(smt_root),
        "smt_siblings": [str(s) for s in siblings],
        "smt_directions": [str(d) for d in directions],
    }

    with open(args.output, "w") as f:
        json.dump(circuit_input, f, indent=2)

    print(f"Generated {args.output}")
    print(f"  xsk HRP:        {xsk_hrp}")
    print(f"  vk HRP:         {vk_hrp if args.vk else xvk_hrp}")
    print(f"  Public key:     {pk_bytes.hex()}")
    print(f"  Scalar (hex):   {scalar.hex()}")
    print(f"  SMT depth:      {args.depth}")
    print(f"  SMT leaf index: {args.index}")
    if used_cli:
        print(f"  SMT builder:    groth16-prover smt CLI (--smt-cli {args.smt_cli})")
    else:
        print(f"  SMT builder:    PYTHON FALLBACK (smt CLI '{args.smt_cli}' unavailable)")
    print(f"  SMT root:       {smt_root}")
    print(f"  MiMC leaf:      {leaf}")
    print("Input generated successfully for CardanoKeyOwnershipSMT circuit.")


if __name__ == "__main__":
    main()