#!/usr/bin/env bash
# Builds and publishes the server without GitHub Actions, with the version in
# Cargo.toml, as the server-vX.Y.Z release (Linux x86_64 and aarch64, and the
# Docker image).
#
#   scripts/release-local.sh status
#   scripts/release-local.sh version server [X.Y.Z]
#   scripts/release-local.sh build server [linux]
#   scripts/release-local.sh publish server [--docker]
#   scripts/release-local.sh deploy server
#   scripts/release-local.sh download server <run-id>
#
# status shows the version, the latest tag and how many commits touched the
# server since then.
#
# version shows the version or changes it (and Cargo.lock).
#
# build compiles it into dist/server/ for Linux x86_64 and aarch64, in Docker
# (scripts/builder.Dockerfile, Ubuntu 22.04) so it runs on Ubuntu 22.04+ and
# Debian 12+; with DOCKER=0 it is built on this machine (which needs what that
# Dockerfile installs).
#
# publish creates the <component>-vX.Y.Z release with the contents of
# dist/<component>/, using the GitHub API (curl, no `gh`). It is created as a
# draft and published once all files are uploaded. If the release already
# exists, the files are added to it.
# With --docker it also pushes the image to GHCR (needs `docker login ghcr.io`
# and buildx with arm64).
#
# deploy installs the server from dist/ (Linux) on this machine, in
# /usr/local/bin. The previous binary is kept as termoak-server.prev and the
# systemd service is restarted. The session holder (termoak-sessions, if
# installed) is not restarted unless its protocol changes or
# RESTART_SESSIONS=1 is set: open sessions survive.
#
# download puts into dist/server/ the binaries of a release.yml run that did
# not get to publish (the id is in the run's URL).
#
# Variables:
#   GITHUB_TOKEN  GitHub token (publish and download). If unset, it is read
#                 from ~/.config/termoak/github-token. Fine-grained, with access to
#                 the TermoakSSH repositories, Contents: Read and write (and
#                 Actions: Read for download)
#   REPO          owner/repository (default: TermoakSSH/server)
#   COMMIT        commit to tag (default: HEAD)
#   VERSION       version for download and publish (default: the manifest's)
#   IMAGE         server Docker image (default: ghcr.io/termoakssh/termoak-server)
#
# Compatible with macOS's bash 3.2.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

die() { echo "error: $*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }

COMPONENTS="server"

# --- components ---------------------------------------------------------------

manifest_of() { # component
  case "$1" in
    server) echo Cargo.toml ;;
    *) die "unknown component: ${1:-} (server)" ;;
  esac
}

title_of() { echo Server; }

# Code the server depends on (for `status`).
paths_of() { echo "src web locales build.rs Cargo.toml Cargo.lock deploy Dockerfile.release"; }

version_of() { # component
  local file v
  file="$(manifest_of "$1")"
  if [[ "$1" == android ]]; then
    v="$(sed -n 's/^termoakVersion=\(.*\)$/\1/p' "$file" | head -1)"
  elif [[ "$1" == ios ]]; then
    v="$(sed -n 's/^ *MARKETING_VERSION: *"\(.*\)"$/\1/p' "$file" | head -1)"
  else
    v="$(sed -n 's/^version = "\(.*\)"/\1/p' "$file" | head -1)"
  fi
  [[ -n "$v" ]] || die "$file has no version = \"X.Y.Z\" line of its own (version.workspace = true?)"
  echo "$v"
}

# A component's latest published tag.
last_tag_of() { git tag -l "$1-v*" --sort=-v:refname | head -1; }

# Component and version from the command line. In build, `version` and `tag`
# always come from the manifest; in download and publish they can be changed
# with VERSION (e.g. for binaries from an earlier release.yml run).
select_component() { # component command
  component="${1:-}"
  [[ -n "$component" ]] || die "missing component: server"
  manifest_of "$component" >/dev/null
  version="$(version_of "$component")"
  if [[ -n "${VERSION:-}" && "$2" != build ]]; then
    version="${VERSION#v}"
  fi
  tag="$component-v$version"
  dist="$root/dist/$component"
}

# Inside Docker the binaries go to another folder so they don't mix with the
# ones built on the host (different glibc).
if [[ -n "${BUILD_TARGET_DIR:-}" ]]; then
  root_target="$BUILD_TARGET_DIR/root"
else
  root_target="$root/target"
fi

# The build image already has them installed (and rustup is read-only there).
add_targets() {
  [[ -n "${TERMOAK_BUILDER:-}" ]] || rustup target add "$@" >/dev/null
}

# --- status and version -------------------------------------------------------

cmd_status() {
  git fetch -q --tags origin 2>/dev/null || true
  printf '%-9s %-9s %-16s %s\n' component version 'latest tag' 'commits since'
  local c v last n note
  for c in $COMPONENTS; do
    v="$(version_of "$c")"
    last="$(last_tag_of "$c")"
    note=""
    if [[ -z "$last" ]]; then
      last="-"
      n="$(git rev-list --count HEAD)"
    else
      # shellcheck disable=SC2046
      n="$(git rev-list --count "$last..HEAD" -- $(paths_of "$c"))"
    fi
    if [[ "$n" != 0 ]] && git rev-parse -q --verify "refs/tags/$c-v$v" >/dev/null; then
      note="  (v$v already published: bump the version before publishing)"
    fi
    printf '%-9s %-9s %-16s %s%s\n' "$c" "$v" "$last" "$n" "$note"
  done
}

cmd_version() { # component [X.Y.Z]
  select_component "${1:-}" version
  local new="${2:-}" file
  if [[ -z "$new" ]]; then
    echo "$version"
    return
  fi
  new="${new#v}"
  [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "\"$new\" is not an X.Y.Z version"
  [[ "$new" != "$version" ]] || die "$component is already at $new"
  file="$(manifest_of "$component")"
  # Only the first `version = ` line.
  awk -v v="$new" '!done && /^version = "/ { print "version = \"" v "\""; done = 1; next } { print }' \
    "$file" >"$file.tmp" && mv "$file.tmp" "$file"
  cargo update -q -p termoak-server
  say "$component: $version → $new ($file and Cargo.lock)"
}

# --- build --------------------------------------------------------------------

# termoak-<component>-vX.Y.Z-<name>.tar.gz (.zip on Windows).
package_bin() { # rust-target name
  local target="$1" name="$2" ext="" bin work d
  [[ "$target" == *windows* ]] && ext=".exe"
  bin=termoak-server
  say "$(title_of "$component") $version: $name"
  cargo build --release --locked --target "$target" --target-dir "$root_target" -p "termoak-$component"
  d="termoak-$component-v$version-$name"
  work="$(mktemp -d)"
  mkdir "$work/$d"
  cp "$root_target/$target/release/$bin$ext" README.md "$work/$d/"
  cp deploy/config.example.toml deploy/termoak-server.service "$work/$d/"
  if [[ -n "$ext" ]]; then
    (cd "$work" && zip -qr "$dist/$d.zip" "$d")
  else
    tar czf "$dist/$d.tar.gz" -C "$work" "$d"
  fi
  rm -rf "$work"
}

build_linux() {
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
  export CC_aarch64_unknown_linux_gnu="${CC_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-gcc}"
  export AR_aarch64_unknown_linux_gnu="${AR_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-ar}"
  add_targets x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
  package_bin x86_64-unknown-linux-gnu linux-x86_64
  package_bin aarch64-unknown-linux-gnu linux-aarch64
}

# Builds linux and windows inside the scripts/builder.Dockerfile image.
build_in_docker() { # platforms...
  command -v docker >/dev/null || die "Docker is missing (or use DOCKER=0 with the tools installed)"
  say "Build image (Ubuntu 22.04)"
  docker build --platform linux/amd64 -t termoak-builder - <scripts/builder.Dockerfile
  # Run as this machine's user so dist/ and target/ stay owned by it.
  # The cargo registry is kept in target/builder so it isn't downloaded every time.
  docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
    -v "$root:/src" -w /src -e HOME=/tmp \
    -e BUILD_TARGET_DIR=/src/target/builder -e CARGO_HOME=/src/target/builder/cargo \
    termoak-builder scripts/release-local.sh build "$component" "$@"
}

cmd_build() { # server [platforms...]
  select_component "${1:-}" build
  shift
  local platforms=("$@") p in_docker=() native=()
  if [[ ${#platforms[@]} -eq 0 ]]; then platforms=(linux); fi
  for p in "${platforms[@]}"; do
    case "$p" in
      linux)
        if [[ -n "${TERMOAK_BUILDER:-}" || "${DOCKER:-1}" == 0 ]]; then native+=("$p"); else in_docker+=("$p"); fi ;;
      *) die "unknown platform: $p (linux)" ;;
    esac
  done

  # The outer call empties dist/<component>/; the one inside Docker adds to it.
  if [[ -z "${TERMOAK_BUILDER:-}" ]]; then
    rm -rf "$dist"
    mkdir -p "$dist"
    echo "$tag" >"$dist/.version"
  fi
  if [[ ${#in_docker[@]} -gt 0 ]]; then build_in_docker "${in_docker[@]}"; fi
  for p in ${native[@]+"${native[@]}"}; do "build_$p"; done

  if [[ -z "${TERMOAK_BUILDER:-}" ]]; then
    say "Done: $tag in dist/$component/"
    ls -l "$dist"
  fi
}

# --- deploy -------------------------------------------------------------------

# Session holder (termoak-sessions): started if it isn't running, and only
# restarted (which drops the sessions) if its protocol changes or
# RESTART_SESSIONS=1 is set.
deploy_holder() {
  systemctl cat termoak-sessions >/dev/null 2>&1 || return 0
  local new running
  new="$(/usr/local/bin/termoak-server holder-protocol)"
  running="$($sudo sh -c 'cat /run/termoak-sessions/*.protocol' 2>/dev/null || true)"
  if ! systemctl is-active -q termoak-sessions; then
    $sudo systemctl start termoak-sessions
    say "termoak-sessions started"
  elif [[ "${RESTART_SESSIONS:-0}" == 1 ]]; then
    say "Restarting the session holder (RESTART_SESSIONS=1): open sessions are dropped"
    $sudo systemctl restart termoak-sessions
  elif [[ "$running" != "$new" ]]; then
    say "The session holder protocol changes (${running:-?} → $new): restarting it, open sessions are dropped"
    $sudo systemctl restart termoak-sessions
  else
    say "Session holder unchanged: open sessions survive"
  fi
}

cmd_deploy() { # server
  select_component "${1:-}" deploy
  [[ "$(uname -s)" == Linux ]] || die "deploy only installs on Linux"
  [[ "$(cat "$dist/.version" 2>/dev/null)" == "$tag" ]] ||
    die "dist/$component/ does not hold $tag: run scripts/release-local.sh build $component first"
  local arch archive work bin sudo=""
  arch="$(uname -m)"
  if [[ "$arch" == arm64 ]]; then arch=aarch64; fi
  archive="$dist/termoak-$component-v$version-linux-$arch.tar.gz"
  [[ -f "$archive" ]] || die "$(basename "$archive") is not in dist/$component/"
  [[ "$(id -u)" == 0 ]] || sudo=sudo
  bin=termoak-server
  work="$(mktemp -d)"
  tar xzf "$archive" -C "$work" --strip-components=1
  "$work/$bin" --version >/dev/null || die "the binary in $(basename "$archive") does not run on this machine"
  if [[ -f /usr/local/bin/$bin ]]; then
    $sudo cp -p "/usr/local/bin/$bin" "/usr/local/bin/$bin.prev"
  fi
  $sudo install -m 755 "$work/$bin" "/usr/local/bin/$bin"
  rm -rf "$work"
  say "Installed /usr/local/bin/$bin ($("/usr/local/bin/$bin" --version))"
  if systemctl cat termoak-server >/dev/null 2>&1; then
    deploy_holder
    $sudo systemctl restart termoak-server
    sleep 2
    if systemctl is-active -q termoak-server; then
      say "termoak-server restarted"
    else
      $sudo journalctl -u termoak-server -n 20 --no-pager || true
      die "termoak-server does not start. To roll back:
  sudo install -m 755 /usr/local/bin/$bin.prev /usr/local/bin/$bin && sudo systemctl restart termoak-server"
    fi
  fi
}

# --- GitHub API (curl) --------------------------------------------------------

github_setup() {
  command -v curl >/dev/null || die "curl is missing"
  command -v python3 >/dev/null || die "python3 is missing (needed to read GitHub's JSON responses)"
  local file="${XDG_CONFIG_HOME:-$HOME/.config}/termoak/github-token"
  github_token="${GITHUB_TOKEN:-}"
  if [[ -z "$github_token" && -f "$file" ]]; then
    github_token="$(tr -d '[:space:]' <"$file")"
  fi
  # Otherwise, the login of the GitHub CLI if it is installed (`gh auth login`).
  if [[ -z "$github_token" ]] && command -v gh >/dev/null; then
    github_token="$(gh auth token 2>/dev/null || true)"
  fi
  [[ -n "$github_token" ]] ||
    die "the GitHub token is missing: GITHUB_TOKEN, $file or \`gh auth login\`"
  # This repository; REPO=owner/repository publishes somewhere else (a fork).
  repo="${REPO:-TermoakSSH/server}"
  [[ "$repo" == */* ]] || die "cannot tell which repository this is: set REPO=owner/repository"
}

# Calls the API. Leaves the response in api_body and the HTTP status in api_status.
github() { # method path-or-url [curl arguments...]
  local method="$1" url="$2" out
  shift 2
  [[ "$url" == https://* ]] || url="https://api.github.com$url"
  # -L: GitHub redirects downloads to its storage (curl does not forward the
  # token to another domain).
  out="$(curl -sS -L -X "$method" -w '\n%{http_code}' \
    -H "Authorization: Bearer $github_token" -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" "$@" "$url")" || die "could not connect to GitHub"
  api_status="${out##*$'\n'}"
  api_body="${out%$'\n'*}"
}
# Like github(), but stops if GitHub answers with an error.
github_ok() { # what-we-were-doing method path [curl arguments...]
  local what="$1"
  shift
  github "$@"
  if [[ "$api_status" != 2* ]]; then
    printf '%s\n' "$api_body" >&2
    die "GitHub answered $api_status when trying to $what"
  fi
}
# Python expression over the JSON response (in `d`).
json() {
  printf '%s' "$api_body" | python3 -c "import json, sys; d = json.load(sys.stdin); v = $1; print('' if v is None else v)"
}
# JSON object from key value pairs. `draft` is a boolean; everything else is
# a string (make_latest too: the API expects "true" or "false").
json_object() {
  python3 -c '
import json, sys
a = sys.argv[1:]
print(json.dumps({k: (v == "true") if k == "draft" else v for k, v in zip(a[::2], a[1::2])}))' "$@"
}

# --- download -----------------------------------------------------------------

cmd_download() { # component id
  select_component "${1:-}" download
  local run="${2:-}" work
  [[ -n "$run" ]] || die "missing run id (the number in its Actions URL)"
  command -v unzip >/dev/null || die "unzip is missing"
  github_setup
  github_ok "list the artifacts of run $run" GET "/repos/$repo/actions/runs/$run/artifacts?per_page=100"
  local urls url
  urls="$(json "'\\n'.join(a['archive_download_url'] for a in d['artifacts'] if a['name'].startswith('$component-') and not a['expired'])")"
  [[ -n "$urls" ]] || die "that run has no $component artifacts (or they expired)"
  work="$(mktemp -d)"
  while IFS= read -r url; do
    curl -fsSL -H "Authorization: Bearer $github_token" -o "$work/a.zip" "$url" ||
      die "could not download an artifact"
    unzip -q -o "$work/a.zip" -d "$work/files"
    rm -f "$work/a.zip"
  done <<<"$urls"
  find "$work" -type f -name "*v$version*" | grep -q . ||
    die "that run is not for $tag: set its version with VERSION=X.Y.Z"
  rm -rf "$dist"
  mkdir -p "$dist"
  find "$work" -type f -exec mv {} "$dist/" \;
  rm -rf "$work"
  echo "$tag" >"$dist/.version"
  say "Artifacts of $tag in dist/$component/"
  ls -l "$dist"
}

# --- publish ------------------------------------------------------------------

push_docker_image() {
  local image pair arch
  image="${IMAGE:-ghcr.io/termoakssh/termoak-server}"
  for pair in x86_64:amd64 aarch64:arm64; do
    arch="${pair##*:}"
    [[ -f "$dist/termoak-server-v$version-linux-${pair%%:*}.tar.gz" ]] ||
      die "the linux-${pair%%:*} server is missing from dist/server/"
    mkdir -p "$dist/$arch"
    tar xzf "$dist/termoak-server-v$version-linux-${pair%%:*}.tar.gz" -C "$dist/$arch" --strip-components=1
  done
  say "Docker image: $image:v$version"
  docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile.release \
    -t "$image:v$version" -t "$image:latest" --push .
  rm -rf "$dist/amd64" "$dist/arm64"
}

cmd_publish() { # component [--docker]
  select_component "${1:-}" publish
  local docker_image=0 commit existing=0 file files=() prev latest id asset_id
  case "${2:-}" in
    --docker)
      docker_image=1
      ;;
    "") ;;
    *) die "unknown option: $2" ;;
  esac
  [[ "$(cat "$dist/.version" 2>/dev/null)" == "$tag" ]] ||
    die "dist/$component/ does not hold $tag: run scripts/release-local.sh build $component first"
  github_setup

  github GET "/repos/$repo/releases/tags/$tag"
  if [[ "$api_status" == 200 ]]; then
    existing=1
    id="$(json 'd["id"]')"
    say "Release $tag already exists: adding the files"
  elif [[ "$api_status" != 404 ]]; then
    printf '%s\n' "$api_body" >&2
    die "GitHub answered $api_status when looking up release $tag (does the token have access to the repository?)"
  else
    commit="${COMMIT:-$(git rev-parse HEAD)}"
    git fetch -q --tags origin 2>/dev/null || true
    [[ -n "$(git branch -r --contains "$commit" 2>/dev/null)" ]] ||
      die "commit $commit is not on GitHub: push it first (git push)"
  fi


  for file in "$dist"/*; do
    [[ -f "$file" ]] && files+=("$file")
  done
  [[ ${#files[@]} -gt 0 ]] || die "nothing to publish in dist/$component/"

  if [[ $existing == 0 ]]; then
    # An earlier attempt that failed halfway leaves a draft: reuse it.
    github_ok "look for drafts" GET "/repos/$repo/releases?per_page=100"
    id="$(json "next((r['id'] for r in d if r['draft'] and r['tag_name'] == '$tag'), None)")"
  fi
  if [[ $existing == 0 && -n "$id" ]]; then
    say "Found a draft of $tag from an earlier attempt: completing it"
  elif [[ $existing == 0 ]]; then
    # Notes since the previous version of this same component.
    prev="$(last_tag_of "$component")"
    if [[ -n "$prev" && "$prev" != "$tag" ]]; then
      github_ok "generate the notes" POST "/repos/$repo/releases/generate-notes" \
        -d "$(json_object tag_name "$tag" target_commitish "$commit" previous_tag_name "$prev")"
    else
      github_ok "generate the notes" POST "/repos/$repo/releases/generate-notes" \
        -d "$(json_object tag_name "$tag" target_commitish "$commit")"
    fi
    say "Creating release $tag in $repo ($commit) as a draft"
    github_ok "create the release" POST "/repos/$repo/releases" \
      -d "$(json_object tag_name "$tag" target_commitish "$commit" \
        name "$(title_of "$component") $version" body "$(json 'd["body"]')" draft true)"
    id="$(json 'd["id"]')"
  fi

  for file in ${files[@]+"${files[@]}"}; do
    # If one with that name already exists (existing release), it is replaced.
    github_ok "read the release" GET "/repos/$repo/releases/$id"
    asset_id="$(json "next((a['id'] for a in d['assets'] if a['name'] == '$(basename "$file")'), None)")"
    if [[ -n "$asset_id" ]]; then
      github_ok "delete $(basename "$file")" DELETE "/repos/$repo/releases/assets/$asset_id"
    fi
    echo "  uploading $(basename "$file")"
    github_ok "upload $(basename "$file")" POST \
      "https://uploads.github.com/repos/$repo/releases/$id/assets?name=$(basename "$file")" \
      -H "Content-Type: application/octet-stream" --data-binary "@$file"
  done

  if [[ $existing == 0 ]]; then
    latest=true
    github_ok "publish the release" PATCH "/repos/$repo/releases/$id" \
      -d "$(json_object draft false make_latest "$latest")"
  fi
  if [[ $docker_image == 1 ]]; then push_docker_image; fi
  say "Published $tag: https://github.com/$repo/releases/tag/$tag"
}

# With exit in every branch bash does not read this file again: it can be
# edited (or git pulled) while it builds.
case "${1:-}" in
  status) cmd_status; exit ;;
  version) shift; cmd_version "$@"; exit ;;
  build) shift; cmd_build "$@"; exit ;;
  publish) shift; cmd_publish "$@"; exit ;;
  deploy) shift; cmd_deploy "$@"; exit ;;
  download) shift; cmd_download "$@"; exit ;;
  *) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 1 ;;
esac
