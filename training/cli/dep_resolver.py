#!/usr/bin/env python3
"""
Production-grade dependency resolver for vpl_slither_scan.py.

Resolves Solidity imports through multiple strategies:
  1. Local project inference: foundry.toml, remappings.txt, hardhat.config.*
  2. npm packages via unpkg CDN with version pinning from package.json
  3. Smart bare-remapping fallback: git clone well-known repos (Uniswap v3, etc.)
  4. Offline mode: prefers ~/.foundry/lib/ and node_modules/
  5. Pragma version auto-detection for solc compatibility
  6. Commit-hash caching for git clones (re-clones only when upstream changes)
"""

import os, re, json, subprocess, tempfile, urllib.request, hashlib
from pathlib import Path
from datetime import datetime, timezone


# -- well-known bare remapping repositories ----------------------

BARE_REMAPPING_REPOS = {
    "v3-core": {
        "repo": "https://github.com/Uniswap/v3-core",
        "branch": "main",
        "src_dir": "contracts",
        "remap_to": "v3-core",
    },
    "v3-periphery": {
        "repo": "https://github.com/Uniswap/v3-periphery",
        "branch": "main",
        "src_dir": "contracts",
        "remap_to": "v3-periphery",
    },
    "permit2": {
        "repo": "https://github.com/Uniswap/permit2",
        "branch": "main",
        "src_dir": "src",
        "remap_to": "permit2",
    },
    "solmate": {
        "repo": "https://github.com/transmissions11/solmate",
        "branch": "main",
        "src_dir": "src",
        "remap_to": "solmate",
    },
    "forge-std": {
        "repo": "https://github.com/foundry-rs/forge-std",
        "branch": "master",
        "src_dir": "src",
        "remap_to": "forge-std",
    },
    "@openzeppelin/contracts": {
        "repo": "https://github.com/OpenZeppelin/openzeppelin-contracts",
        "branch": "master",
        "src_dir": "contracts",
        "remap_to": "@openzeppelin/contracts",
    },
}

# -- cache management --------------------------------------------

CACHE_ROOT = os.path.expanduser("~/.cache/veilpiercer/deps")
os.makedirs(CACHE_ROOT, exist_ok=True)



def detect_project_root(contract_path):
    """Walk up from contract_path to find project root.
    Returns (root_dir, project_type, remote_url).
    project_type: 'foundry', 'hardhat', 'git', or None.
    """
    d = Path(contract_path).parent.resolve()
    for _ in range(6):
        if (d / "foundry.toml").exists():
            url = _get_git_remote(d)
            return str(d), "foundry", url
        for hh in ("hardhat.config.js", "hardhat.config.ts"):
            if (d / hh).exists():
                url = _get_git_remote(d)
                return str(d), "hardhat", url
        if (d / ".git").is_dir():
            url = _get_git_remote(d)
            return str(d), "git", url
        if d.parent == d:
            break
        d = d.parent
    return None, None, None


def _get_git_remote(repo_dir):
    """Extract origin URL from git config."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_dir), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() if r.stdout.strip() else None
    except Exception:
        return None


def suggest_clone(contract_path):
    """If a project root with git remote is found, suggest cloning."""
    root, ptype, url = detect_project_root(contract_path)
    if url and "github.com" in url:
        return (f"Full project context needed. Clone with:\n"
                f"  git clone --depth 1 {url}\n"
                f"  cd $(basename {url} .git) && forge install\n"
                f"  Then run: slither <contract> --solc-remaps @...=lib/...")
    return None


def clone_full_project(remote_url, target_dir=None):
    """Shallow-clone a full project repo. Returns (ok, repo_dir, message)."""
    if target_dir is None:
        name = remote_url.rstrip("/").split("/")[-1].replace(".git", "")
        target_dir = os.path.join(CACHE_ROOT, "projects", name)
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    if os.path.exists(target_dir):
        return True, target_dir, "already cloned"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", remote_url, target_dir],
            capture_output=True, text=True, timeout=120, check=True,
        )
        # Try forge install for foundry projects
        try:
            subprocess.run(
                ["git", "-C", target_dir, "submodule", "update", "--init", "--depth", "1"],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            pass
        return True, target_dir, "cloned"
    except Exception as e:
        return False, target_dir, str(e)


def cached_clone(repo_url, branch="main"):
    """Git clone with commit-hash caching. Skips clone if hash unchanged."""
    cache_key = hashlib.sha256(f"{repo_url}:{branch}".encode()).hexdigest()[:12]
    cache_dir = os.path.join(CACHE_ROOT, cache_key)
    hash_file = os.path.join(cache_dir, ".vp_commit_hash")

    # Get remote HEAD hash
    try:
        remote_ref = subprocess.run(
            ["git", "ls-remote", repo_url, f"refs/heads/{branch}"],
            capture_output=True, text=True, timeout=15,
        )
        remote_hash = remote_ref.stdout.split()[0] if remote_ref.stdout.strip() else None
    except Exception:
        remote_hash = None

    # If cache exists and hash matches, use it
    if remote_hash and os.path.exists(hash_file):
        try:
            with open(hash_file) as f:
                cached_hash = f.read().strip()
            if cached_hash == remote_hash:
                return True, cache_dir, f"using cached {cache_key} (commit {remote_hash[:8]})"
        except Exception:
            pass

    # Otherwise, clone (shallow)
    try:
        if os.path.exists(cache_dir):
            subprocess.run(["rm", "-rf", cache_dir], timeout=10)
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, cache_dir],
            capture_output=True, text=True, timeout=120,
            check=True,
        )
        if remote_hash:
            with open(hash_file, "w") as f:
                f.write(remote_hash)
        return True, cache_dir, f"cloned {cache_key} (commit {remote_hash[:8] if remote_hash else '?'})"
    except Exception as e:
        return False, cache_dir, str(e)


# -- parsing helpers ---------------------------------------------


def parse_pragma(source):
    """Extract Solidity pragma version. Returns '0.8.24' or None."""
    m = re.search(r'pragma\s+solidity\s+[\^~>=]*(\d+\.\d+\.\d+)', source)
    return m.group(1) if m else None


def parse_imports(source):
    return re.findall(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\'];', source)


def categorize_imports(imports):
    npm, bare, relative = [], [], []
    for imp in imports:
        if imp.startswith("./") or imp.startswith("../"):
            relative.append(imp)
        elif imp.startswith("@"):
            npm.append(imp)
        else:
            bare.append(imp)
    return npm, bare, relative


def extract_npm_scope(imp):
    parts = imp.split("/")
    if imp.startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return None


# -- local project inference ------------------------------------


def scan_upward(contract_path, filename, max_levels=4):
    """Search upward from contract_path for a config file."""
    d = Path(contract_path).parent.resolve()
    for _ in range(max_levels):
        candidate = d / filename
        if candidate.exists():
            return str(d), candidate.read_text()
        if d.parent == d:
            break
        d = d.parent
    return None, None


def parse_foundry_toml(content):
    """Extract remappings and solc version from foundry.toml."""
    remappings = []
    solc_version = None
    in_profile = False
    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("[profile"):
            in_profile = True
        if in_profile and "=" in line and not line.startswith("#") and not line.startswith("["):
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key == "solc":
                solc_version = val
            elif key == "remappings" and val.startswith("[") and val.endswith("]"):
                # Parse TOML array: ["a/=b/", "c/=d/"]
                for item in re.findall(r'"([^"]+)"', val):
                    remappings.append(item)
    return remappings, solc_version


def parse_remappings_txt(content):
    """Parse foundry-style remappings.txt lines."""
    return [line.strip() for line in content.split("\n")
            if line.strip() and not line.strip().startswith("#") and "=" in line]


def infer_local_remappings(contract_path):
    """Auto-detect remappings from project config files."""
    all_remappings = []
    solc_version = None

    # 1. Try remappings.txt
    remap_dir, remap_content = scan_upward(contract_path, "remappings.txt")
    if remap_content:
        all_remappings.extend(parse_remappings_txt(remap_content))

    # 2. Try foundry.toml
    foundry_dir, foundry_content = scan_upward(contract_path, "foundry.toml")
    if foundry_content:
        fr, sv = parse_foundry_toml(foundry_content)
        all_remappings.extend(fr)
        if sv:
            solc_version = sv

    return all_remappings, solc_version, foundry_dir


# -- npm package download ----------------------------------------


def download_npm_package(pkg_name, version, scratch_dir):
    """Download Solidity npm package from unpkg CDN."""
    if version:
        url = f"https://unpkg.com/{pkg_name}@{version}/"
    else:
        url = f"https://unpkg.com/{pkg_name}/"

    target = os.path.join(scratch_dir, pkg_name)
    os.makedirs(target, exist_ok=True)

    try:
        req = urllib.request.Request(url + "?meta", headers={"User-Agent": "veilpiercer/1.0"})
        r = urllib.request.urlopen(req, timeout=30)
        meta = json.loads(r.read())
    except Exception as e:
        return False, f"metadata fetch failed: {e}"

    files_list = meta.get("files", [])
    if not isinstance(files_list, list):
        return False, "unexpected metadata format"

    sol_files = [f for f in files_list
                 if isinstance(f, dict) and f.get("path", "").endswith(".sol")]

    downloaded, failed = 0, 0
    for fmeta in sol_files:
        fpath = fmeta["path"]
        furl = url + fpath.lstrip("/")
        dest = os.path.join(target, fpath.lstrip("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            req = urllib.request.Request(furl, headers={"User-Agent": "veilpiercer/1.0"})
            r = urllib.request.urlopen(req, timeout=15)
            with open(dest, "wb") as f:
                f.write(r.read())
            downloaded += 1
        except Exception:
            failed += 1

    if downloaded == 0:
        return False, f"0/{len(sol_files)} files downloaded"
    return True, f"{downloaded}/{len(sol_files)} .sol"


def get_package_version_from_json(contract_path):
    """Find package.json and extract a package version."""
    _, pkg_json = scan_upward(contract_path, "package.json")
    if not pkg_json:
        return None, {}
    try:
        pkg = json.loads(pkg_json)
        deps = {}
        deps.update(pkg.get("dependencies", {}))
        deps.update(pkg.get("devDependencies", {}))
        return pkg, deps
    except json.JSONDecodeError:
        return None, {}


# -- offline mode -------------------------------------------------


def find_offline_remappings(contract_path, npm_imports, bare_imports):
    """Find local dependency installs across multiple paths.

    Checks (in priority order):
      1. node_modules/ in project root and globally
      2. lib/ in project root (Foundry submodules)
      3. ~/.foundry/lib/ (Foundry cache)
      4. ~/.cache/foundry/ (Foundry build cache)
      5. ~/.svm/ (solc version manager)
    """
    remappings = []
    found = set()

    # Build search paths from contract location
    contract_dir = Path(contract_path).parent.resolve()
    search_roots = []

    # 1. Project-level node_modules (walk upward up to 4 levels)
    d = contract_dir
    for _ in range(4):
        nm = d / "node_modules"
        if nm.is_dir():
            search_roots.append((str(nm), "node_modules (project)"))
        lib_dir = d / "lib"
        if lib_dir.is_dir():
            search_roots.append((str(lib_dir), "lib (Foundry submodules)"))
        if d.parent == d:
            break
        d = d.parent

    # 2. Global paths
    for path, label in [
        ("~/.foundry/lib", "Foundry lib"),
        ("~/node_modules", "global node_modules"),
        ("~/.cache/foundry", "Foundry cache"),
    ]:
        p = os.path.expanduser(path)
        if os.path.isdir(p):
            search_roots.append((p, label))

    # For each npm import, try to find it in node_modules
    for imp in npm_imports:
        pkg = extract_npm_scope(imp)
        if pkg is None or pkg in found:
            continue
        # npm package name format: @scope/pkg → node_modules/@scope/pkg
        for root, label in search_roots:
            candidate = os.path.join(root, pkg)
            if os.path.isdir(candidate):
                src = _find_solidity_src(candidate)
                if src:
                    remappings.append(f"{pkg}/={src}/")
                    found.add(pkg)
                    break

    # For bare imports, try to find matching directory names
    for imp in bare_imports:
        prefix = imp.split("/")[0] if "/" in imp else imp
        if prefix in found or prefix.startswith("."):
            continue
        for root, label in search_roots:
            candidate = os.path.join(root, prefix)
            if os.path.isdir(candidate):
                src = _find_solidity_src(candidate)
                if src:
                    remappings.append(f"{prefix}/={src}/")
                    found.add(prefix)
                    break

    return remappings


def _find_solidity_src(pkg_dir):
    """Find the Solidity source directory within a package.
    Checks contracts/, src/, or the package root."""
    for sub in ("contracts", "src", ""):
        full = os.path.join(pkg_dir, sub) if sub else pkg_dir
        if os.path.isdir(full) and any(f.endswith(".sol") for f in os.listdir(full)[:10]):
            return full
    return None


# -- main resolver -------------------------------------------------


def resolve_dependencies(contract_path, scratch_dir=None, prefer_offline=True, privacy_mode=False, auto_clone=False):
    """
    Multi-strategy dependency resolution for a Solidity contract.
    Returns: (remappings_path, success, report, solc_version)

    Strategy order:
      1. Offline (~/.foundry/lib/, node_modules/)
      2. Foundry.toml / remappings.txt from parent dirs
      3. npm packages via unpkg CDN
      4. Bare remapping fallback via git clone
    """
    with open(contract_path) as f:
        source = f.read()

    imports = parse_imports(source)
    npm_imports, bare_imports, relative_imports = categorize_imports(imports)
    pragma_ver = parse_pragma(source)

    if scratch_dir is None:
        scratch_dir = tempfile.mkdtemp(prefix="vp_deps_")

    report = []
    report.append(f"  Parsed {len(imports)} imports ({len(npm_imports)} npm, "
                  f"{len(bare_imports)} bare, {len(relative_imports)} relative)")

    all_remappings = []

    # -- Strategy 1: Offline mode ---------------------------------
    if prefer_offline:
        offline_map = find_offline_remappings(contract_path, npm_imports, bare_imports)
        if offline_map:
            all_remappings.extend(offline_map)
            report.append(f"  [OFFLINE] Found {len(offline_map)} local remappings")

    # -- Strategy 2: Foundry.toml / remappings.txt ---------------
    local_remaps, foundry_solc, foundry_dir = infer_local_remappings(contract_path)
    if local_remaps:
        all_remappings.extend(local_remaps)
        report.append(f"  [FOUNDRY] {len(local_remaps)} remappings from project config")
    if foundry_solc:
        report.append(f"  [FOUNDRY] solc version: {foundry_solc}")

    # Use foundry solc version, fall back to pragma
    solc_version = foundry_solc or pragma_ver
    if solc_version:
        report.append(f"  [SOLC] Target version: {solc_version}")

    # -- Strategy 3: npm packages ---------------------------------
    _, package_deps = get_package_version_from_json(contract_path)
    resolved_npm = set()
    npm_failures = {}

    for imp in npm_imports:
        pkg = extract_npm_scope(imp)
        if pkg is None or pkg in resolved_npm:
            continue
        version = package_deps.get(pkg, "").lstrip("^~") if package_deps else None
        ok, msg = download_npm_package(pkg, version, scratch_dir)
        if ok:
            resolved_npm.add(pkg)
            all_remappings.append(f"{pkg}/={scratch_dir}/{pkg}/")
            report.append(f"  [NPM] {pkg}: {msg}")
        else:
            npm_failures[pkg] = msg
            report.append(f"  [NPM] {pkg}: FAILED - {msg}")

    # -- Strategy 4: Bare remapping fallback ----------------------
    bare_prefixes = set()
    for imp in bare_imports:
        parts = imp.split("/")
        if len(parts) >= 1:
            bare_prefixes.add(parts[0])

    resolved_bare = {}
    for prefix in bare_prefixes:
        if prefix in BARE_REMAPPING_REPOS:
            cfg = BARE_REMAPPING_REPOS[prefix]
            ok, repo_dir, msg = cached_clone(cfg["repo"], cfg["branch"])
            if ok:
                src = os.path.join(repo_dir, cfg["src_dir"])
                if os.path.isdir(src):
                    remap_to = cfg["remap_to"]
                    all_remappings.append(f"{remap_to}/={src}/")
                    resolved_bare[prefix] = repo_dir
                    report.append(f"  [GIT] {prefix}: {msg}")
                else:
                    report.append(f"  [GIT] {prefix}: cloned but no {cfg['src_dir']}/ dir")
            else:
                report.append(f"  [GIT] {prefix}: {msg}")

    # -- Build remappings ------------------------------------------
    report.append("")

    unresolved_bare = [b for b in bare_imports
                       if b.split("/")[0] not in resolved_bare]
    unresolved_relative = list(relative_imports)

    success = (len(npm_failures) == 0
               and len(resolved_bare) + len(resolved_npm) + len(local_remaps) > 0)

    # Write remappings file
    remap_path = os.path.join(scratch_dir, "remappings.txt")
    with open(remap_path, "w") as f:
        f.write("\n".join(all_remappings))

    if privacy_mode:
        redacted = []
        for line in report:
            # Strip package names, URLs, repo paths, and version strings
            line = re.sub(r'@\S+/\S+', '<npm-package>', line)
            line = re.sub(r'https?://\S+', '<url>', line)
            line = re.sub(r'/[\w/.]+/[\w/]*cache/veilpiercer/[\w/]+', '<cache-dir>', line)
            line = re.sub(r'commit \w{8}', 'commit <hash>', line)
            line = re.sub(r'\d+/\d+ \.sol', 'N/N .sol', line)
            redacted.append(line)
        report = redacted
    # -- Strategy 5: Local project root mapping for relative imports --
    if unresolved_relative:
        total_rel = len(unresolved_relative)
        root, ptype, url = detect_project_root(contract_path)
        report.append("")
        if root:
            # Found a local project root — add it as remapping directly
            # Find src/ or contracts/ subdirectory containing the contract
            contract_name = os.path.basename(contract_path)
            for src_dir in ("", "src", "contracts"):
                full = os.path.join(root, src_dir) if src_dir else root
                if os.path.isdir(full) and os.path.exists(os.path.join(full, contract_name)):
                    all_remappings.append(f".={full}/")
                    resolved_count = sum(1 for r in relative_imports
                                         if os.path.exists(os.path.join(full, r.lstrip("./"))))
                    unresolved_relative[:] = [r for r in unresolved_relative
                                              if not os.path.exists(os.path.join(full, r.lstrip("./")))]
                    display_root = "<project>" if privacy_mode else root
                    report.append(f"  [REPO] Using local project root: {display_root}")
                    report.append(f"  [REPO] Remapping: .={full}/" if not privacy_mode else "")
                    report.append(f"  [REPO] Resolved {resolved_count}/{total_rel} relative imports via local project root.")
                    break
            else:
                report.append(f"  [REPO] Project root found but can't map contract path.")
        if url and "github.com" in url and auto_clone and unresolved_relative:
            ok, repo_dir, msg = clone_full_project(url)
            if ok:
                for src_dir in ("src", "contracts", ""):
                    full = os.path.join(repo_dir, src_dir) if src_dir else repo_dir
                    if os.path.isdir(full) and os.path.exists(os.path.join(full, contract_name)):
                        all_remappings.append(f".={full}/")
                        unresolved_relative.clear()
                        report.append(f"  [REPO] Auto-cloned project: {msg}")
                        report.append(f"  [REPO] All {len(relative_imports)} relative imports resolved.")
                        break
        elif url and "github.com" in url and not root and unresolved_relative:
            report.append(f"  [REPO] Remote detected: {url}")
            report.append(f"  [REPO] Run with --auto-clone to clone automatically, or:")
            report.append(f"  [REPO]   git clone --depth 1 {url}")
        elif unresolved_relative:
            if not root:
                report.append("  [REPO] Relative imports require full project context.")
                report.append("  [REPO] Clone the project or use --project-root <path>.")


    if unresolved_bare:
        report.append(f"  UNRESOLVED bare ({len(unresolved_bare)}):")
        for b in unresolved_bare[:6]:
            report.append(f"    - {b}")
    if unresolved_relative:
        report.append(f"  UNRESOLVED relative ({len(unresolved_relative)}):")
        for r in unresolved_relative[:4]:
            display = re.sub(r'[\w/]+/', '<path>/', r) if privacy_mode else r
            report.append(f"    - {display}")
    
    return remap_path if all_remappings else None, success, report, solc_version


# -- demo ----------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 dep_resolver.py <contract.sol>")
        sys.exit(1)

    contract = sys.argv[1]
    if not os.path.exists(contract):
        print(f"File not found: {contract}")
        sys.exit(1)

    remap_path, ok, report, solc_ver = resolve_dependencies(contract)
    for line in report:
        print(line)
    if remap_path:
        print(f"\n  Remappings ({os.path.basename(remap_path)}):")
        with open(remap_path) as f:
            for line in f.read().strip().split("\n"):
                print(f"    {line}")
    total_resolved = sum(1 for l in report if l.strip().startswith("["))
    print(f"\n  Overall: {total_resolved} resolution strategies applied")