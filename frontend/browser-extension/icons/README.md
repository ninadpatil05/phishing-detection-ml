# Phishing Detection Browser Extension Icons

Since the image generation service is unavailable, you'll need to create icons manually.

## Required Icons

Create three PNG icons with these dimensions:
- **icon16.png**: 16×16 pixels
- **icon48.png**: 48×48 pixels  
- **icon128.png**: 128×128 pixels

## Design Recommendations

**Shield with Checkmark:**
- Background: Gradient from blue (#60a5fa) to purple (#a78bfa)
- Shield icon in the center
- Optional checkmark or lock symbol inside
- Flat design style
- Rounded edges

## Quick Creation Options

### Option 1: Use an Icon Generator
Visit: https://www.favicon-generator.org/
- Upload a simple shield SVG
- Download all sizes

### Option 2: Use Figma/Canva
- Create 128×128 artboard
- Design shield icon
- Export as PNG at 16, 48, and 128px

### Option 3: Use Emoji as Placeholder
For testing, you can use text-to-icon generators:
- Use 🛡️ shield emoji
- Convert to PNG at each size

## Installation Note

The extension will not load without valid icon files. Place all three files in the `icons/` directory before installing the extension in Chrome.
