Each YAML file is the CRC32 with the .yml extension, e.g. `E5F09F49.yml`.

This CRC32 is based off the 8-character ID-looking thing at the end of the filename, for example: `[One Pace][1] Romance Dawn 01 [1080p][E5F09F49].mkv`

The contents of the `.yml` file:

```
season: 1
episode: 1

title: Romance Dawn, the Dawn of an Adventure
# originaltitle:
# sorttitle:
description: Influenced by the straw-hat-wearing pirate Red-Haired Shanks, an enthusiastic young boy named Monkey D. Luffy dreams of one day becoming King of the Pirates.
manga_chapters: 1
anime_episodes: Episode of East Blue, 312 (Intro)

# rating: TV-14
released: 2025-05-03 00:42

# hashes: 
#  crc32: E5F09F49
#  blake2: cd1da1484f997a73
```

If there's two clashing CRC32's:
- The original `.yml` should be renamed to end with `_1.yml` instead, with the other one renamed to add `_2.yml`.
  - This ends up as two files, `E5F09F49_1.yml` and `E5F09F49_2.yml`.
- The `hashes` section becomes required, not optional.
  - The value of `crc32` is the original CRC32. (`E5F09F49`)
  - The value of `blake2` is the first 16 characters of the blake2s hash of the file.
