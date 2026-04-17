# #337 — Install script: zip/unzip not detected on Arch Linux

## Problem

On Arch Linux, the installer does not detect `zip` / `unzip` even when
they are installed (or reports them missing when they're available via a
different path / package manager idiom). Dependency checks need to work
across distros.

## Fix

Probe for the tool via `command -v zip` / `command -v unzip` rather than
assuming a particular package name. Fall back to suggesting the
appropriate install command per distro (`pacman -S unzip` on Arch,
`apt install unzip` on Debian, etc.).

## Source

From `issues/new-issue-please-sort`.
