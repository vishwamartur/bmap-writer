# bmap-writer

`bmap-writer` is a command-line utility designed to efficiently write disk images to storage devices using block mapping (BMAP). 
It serves as a lightweight alternative to the Yocto BMAP tool, specifically for embedded systems. 
Unlike the Yocto BMAP tool, `bmap-writer` is C++ based does not require Python and focuses solely on writing an image.

## Key Features

- **Alternative to Yocto BMAP Tool**: Provides a lightweight alternative specifically for embedded systems.
- **No Python Required**: Does not require Python, making it easier to integrate into various environments.
- **Support for Compressed Images**: Handles gzip and xz compressed images, decompressing them on-the-fly during the writing process.
- **Checksum Verification**: Ensures data integrity by verifying checksums for each block.
- **Efficient Writing**: Writes only the necessary blocks, reducing the overall write time and wear on storage devices.

## How It Works

1. **Generate a BMAP File**: Create a BMAP file for your disk image using `bmaptool`.
2. **Write the Image**: Use `bmap-writer` to write the image to your target device, specifying the BMAP file for efficient block mapping.

## Example Usage

```
bmap-writer <image-file> <bmap-file> <target-device>
```