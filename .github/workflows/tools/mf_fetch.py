#!/usr/bin/env python3
"""
mf_fetch.py — Fast fetch from an Android repo manifest (no `repo` needed).

Highlights
- Parses manifest XML (+ local <include file="...">), <default>, <remote>, <project>, <remove-project>
- Optional groups filter (intersection)
- Two fetch modes:
    * tarball (default): AOSP Gitiles (+archive), GitHub (codeload), GitLab (/-/archive) via aria2c
    * git fallback: shallow clone + checkout (enable with --allow-git-fallback)
- Recreates the same directory layout as `repo sync` (extracts into each <project path>)
- Applies copyfile/linkfile (symlink preferred; copies as fallback)
- Writes _fetch_report.json for reproducibility

Requirements: Python 3.8+, aria2c, git, tar
"""

import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------- Utilities ----------

def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)

def run(cmd, cwd: Optional[Path] = None):
    eprint(">", " ".join(cmd))
    subprocess.check_call(cmd, cwd=str(cwd) if cwd else None)

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def slug(s: str) -> str:
    return s.replace("/", "_").replace(":", "_")

def is_within_directory(directory: str, target: str) -> bool:
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    return os.path.commonprefix([abs_directory, abs_target]) == abs_directory

def _same(a: Path, b: Path) -> bool:
    """Return True if a and b refer to the same file/dir (considering symlinks)."""
    try:
        if a.resolve() == b.resolve():
            return True
        return os.path.exists(a) and os.path.exists(b) and os.path.samefile(a, b)
    except Exception:
        return False

# ---------- Archive extraction helpers ----------

def extract_gitiles_flat_tar(tar_path: Path, dest: Path):
    """Gitiles +archive tarballs are 'flat' (no top-level dir)."""
    ensure_dir(dest)
    with tarfile.open(tar_path, "r:gz") as tf:
        for m in tf.getmembers():
            target = dest / m.name
            if not is_within_directory(str(dest), str(target)):
                raise Exception("Path traversal in tar (gitiles)")
        tf.extractall(dest)

def extract_strip_topdir_tar(tar_path: Path, dest: Path):
    """GitHub/GitLab archives have a single top-level dir; strip it."""
    ensure_dir(dest)
    with tarfile.open(tar_path, "r:gz") as tf:
        def members_stripped():
            for m in tf.getmembers():
                p = Path(m.name)
                new_parts = p.parts[1:] if len(p.parts) > 1 else ()
                if not new_parts:
                    continue
                m2 = tarfile.TarInfo(str(Path(*new_parts)))
                m2.size = m.size
                m2.mode = m.mode
                m2.mtime = m.mtime
                m2.type = m.type
                m2.linkname = m.linkname
                m2.uid = m.uid
                m2.gid = m.gid
                yield m, m2

        for orig, m2 in members_stripped():
            target = dest / m2.name
            if not is_within_directory(str(dest), str(target)):
                raise Exception("Path traversal in tar (strip-topdir)")
            if orig.isdir():
                ensure_dir(target)
            elif orig.issym():
                ensure_dir(target.parent)
                try:
                    if target.exists() or target.is_symlink():
                        target.unlink()
                    os.symlink(orig.linkname, target, target_is_directory=False)
                except Exception:
                    with open(target, "w", encoding="utf-8") as f:
                        f.write(orig.linkname)
            elif orig.islnk():
                ensure_dir(target.parent)
                src_inside = dest / m2.linkname
                if src_inside.exists():
                    shutil.copy2(src_inside, target)
            else:
                ensure_dir(target.parent)
                fobj = tf.extractfile(orig)
                if fobj is None:
                    continue
                with open(target, "wb") as out:
                    shutil.copyfileobj(fobj, out)
                os.utime(target, (m2.mtime, m2.mtime))

# ---------- URL guessers ----------

def guess_tarball_url(remote_fetch: str, name: str, revision: str) -> Optional[Tuple[str, str]]:
    """
    Return (url, flavor) where flavor in {"gitiles","github","gitlab"} if a tarball URL can be built.
    - Gitiles: https://...googlesource.com/<name>/+archive/<revision>.tar.gz
    - GitHub : https://codeload.github.com/<owner>/<repo>/tar.gz/<revision>
               Accepts remote fetch in forms:
                  https://github.com/<owner>
                  https://github.com/<owner>/<repo>.git
                  git@github.com:<owner>/<repo>.git
    - GitLab : <remote>/<name>/-/archive/<revision>/<repo>-<revision>.tar.gz (best-effort; repo is last segment)
    """
    rf = remote_fetch.rstrip("/")
    low = rf.lower()

    # Gitiles
    if "googlesource.com" in low:
        return (f"{rf}/{name}/+archive/{revision}.tar.gz", "gitiles")

    # GitHub
    if "github.com" in low:
        owner = None
        repo = None
        if low.startswith("git@github.com:"):
            rest = rf.split(":", 1)[1]
            if rest.endswith(".git"):
                rest = rest[:-4]
            parts = rest.split("/", 2)
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
        else:
            try:
                after = rf.split("github.com", 1)[1].lstrip("/")
            except IndexError:
                after = ""
            parts = [p for p in after.split("/") if p]
            if len(parts) == 1:
                owner = parts[0]
                repo = name.split("/")[-1]
            elif len(parts) >= 2:
                owner, repo = parts[0], parts[1]
            if repo and repo.endswith(".git"):
                repo = repo[:-4]
        if owner and repo:
            return (f"https://codeload.github.com/{owner}/{repo}/tar.gz/{revision}", "github")

    # GitLab-like (CodeLinaro, self-hosted GitLab, etc.)
    if any(k in low for k in (".gitlab", "gitlab.", "/gitlab/", "git.codelinaro.org")) or low.startswith("http"):
        repo_last = name.split("/")[-1]
        if repo_last.endswith(".git"):
            repo_last = repo_last[:-4]
        return (f"{rf}/{name}/-/archive/{revision}/{repo_last}-{revision}.tar.gz", "gitlab")

    return None

# ---------- Manifest parsing ----------

class Manifest:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.remotes: Dict[str, str] = {}
        self.default_remote: Optional[str] = None
        self.default_revision: Optional[str] = None
        self.projects: List[dict] = []
        self.remove_projects = set()

    def load(self, xml_path: Path):
        self._parse(xml_path)

    def _parse(self, xml_path: Path):
        tree = ET.parse(xml_path)
        root = tree.getroot()

        default = root.find("default")
        if default is not None:
            self.default_remote = default.get("remote", self.default_remote)
            self.default_revision = default.get("revision", self.default_revision)

        for r in root.findall("remote"):
            n = r.get("name")
            f = r.get("fetch")
            if n and f:
                self.remotes[n] = f.rstrip("/")

        # local includes only
        for inc in root.findall("include"):
            f = inc.get("file")
            if not f:
                continue
            inc_path = (xml_path.parent / f).resolve()
            if not inc_path.exists():
                raise FileNotFoundError(f"Included manifest not found: {f} -> {inc_path}")
            self._parse(inc_path)

        for rp in root.findall("remove-project"):
            n = rp.get("name")
            if n:
                self.remove_projects.add(n)

        for p in root.findall("project"):
            name = p.get("name")
            if not name or name in self.remove_projects:
                continue
            proj = {
                "name": name,
                "path": p.get("path") or name,
                "remote": self.remotes.get(p.get("remote") or self.default_remote or "", ""),
                "revision": p.get("revision") or self.default_revision or "master",
                "groups": [g.strip() for g in (p.get("groups") or "").split(",") if g.strip()],
                "copylinks": [],  # (kind, src, dest)
            }
            for cf in p.findall("copyfile"):
                src = cf.get("src"); dest = cf.get("dest")
                if src and dest:
                    proj["copylinks"].append(("copy", src, dest))
            for lf in p.findall("linkfile"):
                src = lf.get("src"); dest = lf.get("dest")
                if src and dest:
                    proj["copylinks"].append(("link", src, dest))
            self.projects.append(proj)

# ---------- Fetcher ----------

class Fetcher:
    def __init__(self, args, manifest: Manifest, root: Path):
        self.args = args
        self.m = manifest
        self.root = root
        self.tmp = root / (args.tmpdir or "._mf_tmp")
        ensure_dir(self.tmp)
        self.report = []
        self.lock = threading.Lock()

    def _incl_groups(self, groups: List[str]) -> bool:
        if not self.args.groups:
            return True
        if not groups:
            return True
        return bool(set(self.args.groups) & set(groups))

    def _do_copylinks(self, proj_root: Path, items: List[Tuple[str, str, str]]):
        """Apply <copyfile>/<linkfile> from the manifest with safe overwrites."""
        if self.args.no_copylinks or not items:
            return

        for kind, src, dest in items:
            src_path = (proj_root / src).resolve()
            dest_path = (self.root / dest).resolve()

            if not src_path.exists():
                eprint(f"[WARN] copy/link src missing: {src_path}")
                continue

            ensure_dir(dest_path.parent)

            # If src and dest resolve to the same entity, skip to avoid "same file" errors
            if _same(src_path, dest_path):
                continue

            if kind == "copy":
                # If target exists and type mismatches, remove first
                if dest_path.exists():
                    if dest_path.is_dir() and not src_path.is_dir():
                        shutil.rmtree(dest_path)
                    elif dest_path.is_file() and src_path.is_dir():
                        dest_path.unlink()

                if src_path.is_dir():
                    shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_path, dest_path)

            else:  # link
                # If already the correct symlink, skip
                if dest_path.is_symlink():
                    try:
                        if Path(os.readlink(dest_path)).resolve() == src_path:
                            continue
                    except OSError:
                        pass
                    dest_path.unlink()
                elif dest_path.exists():
                    if dest_path.is_dir():
                        shutil.rmtree(dest_path)
                    else:
                        dest_path.unlink()

                try:
                    os.symlink(src_path, dest_path, target_is_directory=src_path.is_dir())
                except Exception:
                    if src_path.is_dir():
                        shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src_path, dest_path)

    def _git_checkout(self, url: str, rev: str, dest: Path):
        ensure_dir(dest.parent)
        if not (dest / ".git").exists():
            run(["git", "init", str(dest)])
            run(["git", "remote", "add", "origin", url], cwd=dest)
        run(["git", "fetch", "--depth=1", "origin", rev], cwd=dest)
        run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest)

    def _fetch_one(self, proj: dict):
        if not self._incl_groups(proj["groups"]):
            eprint(f"[skip groups] {proj['name']}")
            return

        name = proj["name"]
        path = proj["path"]
        rev = proj["revision"]
        remote = proj["remote"]
        if not remote:
            raise RuntimeError(f"Project {name} has no remote resolved. Check <default remote> or per-project remote.")

        dest = (self.root / path).resolve()
        used = None

        try:
            if self.args.mode == "tar":
                guess = guess_tarball_url(remote, name, rev)
                if not guess:
                    raise RuntimeError("No tarball URL rule for this remote")
                url, flavor = guess
                tmp = self.tmp / f"{slug(name)}_{slug(rev)}.tar.gz"
                if not self.args.dry_run:
                    ensure_dir(tmp.parent)
                    run(["aria2c", "-x", str(self.args.connections), "-s", str(self.args.connections),
                         "-c", "-o", tmp.name, "-d", str(tmp.parent), url])
                    if flavor == "gitiles":
                        extract_gitiles_flat_tar(tmp, dest)
                    else:
                        extract_strip_topdir_tar(tmp, dest)
                used = {"source": "tarball", "url": url, "flavor": flavor, "archive": str(tmp)}
            else:
                raise RuntimeError("force git")
        except Exception as e:
            if self.args.allow_git_fallback:
                eprint(f"[tar -> git] {name}: {e}")
                url = remote.rstrip("/") + "/" + name
                if not url.endswith(".git"):
                    url += ".git"
                if not self.args.dry_run:
                    self._git_checkout(url, rev, dest)
                used = {"source": "git", "url": url}
            else:
                raise

        if not self.args.dry_run:
            self._do_copylinks(dest, proj.get("copylinks", []))

        with self.lock:
            self.report.append({
                "name": name,
                "path": path,
                "remote": remote,
                "revision": rev,
                "used": used,
                "groups": proj.get("groups", []),
            })

    def run(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.jobs) as ex:
            futures = [ex.submit(self._fetch_one, p) for p in self.m.projects]
            for f in concurrent.futures.as_completed(futures):
                f.result()
        with open(self.root / "_fetch_report.json", "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False)
        eprint("Report written to _fetch_report.json")

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Fast fetch from Android repo manifest using aria2c tarballs (with git fallback).")
    ap.add_argument("-m", "--manifest", required=True, help="Path to manifest XML (supports local <include file=...>)")
    ap.add_argument("-C", "--chdir", default=".", help="Target root directory (default: current working dir)")
    ap.add_argument("-j", "--jobs", type=int, default=4, help="Parallel downloads")
    ap.add_argument("-x", "--connections", type=int, default=16, help="Connections per download (aria2c -x/-s)")
    ap.add_argument("--mode", choices=["tar", "git"], default="tar", help="Prefer tarball mode or force git")
    ap.add_argument("--allow-git-fallback", action="store_true", help="Fallback to shallow git when tarball fails/unavailable")
    ap.add_argument("--groups", type=lambda s: [x.strip() for x in s.split(",") if x.strip()], default=None,
                    help="Comma-separated group names to include (intersection). Default: include all.")
    ap.add_argument("--tmpdir", default="._mf_tmp", help="Where to store downloaded archives")
    ap.add_argument("--no-copylinks", action="store_true", help="Disable copyfile/linkfile actions")
    ap.add_argument("--dry-run", action="store_true", help="Plan only, no downloads/extracts")
    args = ap.parse_args()

    root = Path(args.chdir).resolve()
    ensure_dir(root)

    m = Manifest(base_dir=root)
    m.load(Path(args.manifest).resolve())
    eprint(f"Parsed projects: {len(m.projects)} | Remotes: {len(m.remotes)} | default remote={m.default_remote}")

    f = Fetcher(args, m, root)
    f.run()

if __name__ == "__main__":
    main()
