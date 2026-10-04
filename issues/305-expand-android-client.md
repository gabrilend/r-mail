# Expand Android client (collected ideas)

## Current Behavior

The app is as #new-the-android-screens describes.  This file collects
ideas for it, to be built together; one is done (the sync error stays
visible until a sync succeeds, #317).


## Sync error display ✓
- Error banner now stays visible until a sync actually succeeds
- Fixed: removed the `_syncError.value = null` from sync start,
  moved it to the success branch

## Intended Behavior
(add here as they come up)

## Suggested Implementation Steps

1. When the list holds enough, give each idea its own issue in phase 8,
   then build them as one batch.

## Status

Collecting ideas. Implement as a batch.
