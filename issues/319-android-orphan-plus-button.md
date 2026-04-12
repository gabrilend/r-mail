# #319 — Investigate or remove orphan + button on Android

## Problem

A + button in the Android app appears to do nothing when tapped. The
exact screen where this was noticed is not recorded, and the app has
several + buttons across different screens.

## Action

1. Enumerate every `+` button in the Android app: which screen, which
   top-bar/bottom-bar slot, and what it does (or is supposed to do).
2. Identify which one is the dead button.
3. Either wire it up to the intended function (suspected: add
   attachments) or remove it.

## Source

From `rmail-android-plus-button-in-compose-screen`.
