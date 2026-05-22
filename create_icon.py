"""
=============================================================
  SENTINELHOME101 — Icon Generator
  File: create_icon.py

  Generates the SentinelHome101 icon as a proper Windows
  .ico file containing all required sizes:
  16x16, 24x24, 32x32, 48x48, 64x64, 128x128, 256x256

  The icon design:
  - Pentagon shield shape (pointed bottom)
  - Wire house outline (low opacity strokes, no fill)
  - Solid ghost white sword (wide blade, tapered tip,
    curved crossguard, small flat ellipse pommel)

  Run this script once before building the exe:
      python create_icon.py

  Requires Pillow (already installed):
      pip install pillow
=============================================================
"""

from PIL import Image, ImageDraw
import os
import math


def draw_icon(size, dark_mode=True):
    """
    Draws the SentinelHome101 icon at the specified size.

    Parameters:
        size      (int) : Icon size in pixels (square).
        dark_mode (bool): True = dark bg / white sword,
                          False = white bg / dark sword.

    Returns:
        PIL.Image: The rendered icon image with transparency.
    """
    # Colors
    if dark_mode:
        bg_color     = (13, 17, 23, 255)       # #0d1117 charcoal
        border_color = (28, 33, 40, 255)        # #1c2128 subtle border
        sword_color  = (241, 245, 249, 255)     # #f1f5f9 ghost white
        house_color  = (241, 245, 249, 80)      # ghost white 30% opacity
    else:
        bg_color     = (255, 255, 255, 255)     # white
        border_color = (226, 232, 240, 255)     # #e2e8f0
        sword_color  = (13, 17, 23, 255)        # #0d1117 dark
        house_color  = (13, 17, 23, 80)         # dark 30% opacity

    # Create transparent base image
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    s = size  # Shorthand

    # -------------------------------------------------------
    # SHIELD SHAPE
    # Pentagon: wide top, pointed bottom
    # Points: top-left, top-right, right, bottom-point, left
    # -------------------------------------------------------
    margin = max(1, s * 0.02)
    pad = margin

    shield_pts = [
        (pad,           s * 0.18),   # Top left
        (s - pad,       s * 0.18),   # Top right
        (s - pad,       s * 0.68),   # Bottom right
        (s * 0.5,       s - pad),    # Bottom point
        (pad,           s * 0.68),   # Bottom left
    ]

    # Draw shield background
    draw.polygon(shield_pts, fill=bg_color)

    # Draw shield border
    border_w = max(1, int(s * 0.025))
    draw.polygon(shield_pts, outline=border_color)

    # -------------------------------------------------------
    # HOUSE OUTLINE (wire — strokes only, no fill)
    # -------------------------------------------------------
    # House bounds within the shield
    hx1 = s * 0.15    # Left wall X
    hx2 = s * 0.85    # Right wall X
    hcx = s * 0.5     # Center X (roof peak)
    hy_peak  = s * 0.22   # Roof peak Y
    hy_eave  = s * 0.42   # Eave (where roof meets walls) Y
    hy_floor = s * 0.68   # Floor Y

    house_pts = [
        (hcx,  hy_peak),   # Roof peak
        (hx2,  hy_eave),   # Right eave
        (hx2,  hy_floor),  # Bottom right
        (hx1,  hy_floor),  # Bottom left
        (hx1,  hy_eave),   # Left eave
    ]

    hw = max(1, int(s * 0.03))   # House line width

    # Draw house walls and floor (low opacity)
    draw.polygon(house_pts, outline=house_color)

    # Draw roof lines slightly brighter
    roof_color = (sword_color[0], sword_color[1], sword_color[2], 140)
    draw.line([(hcx, hy_peak), (hx2, hy_eave)],
              fill=roof_color, width=hw)
    draw.line([(hcx, hy_peak), (hx1, hy_eave)],
              fill=roof_color, width=hw)

    # -------------------------------------------------------
    # SWORD (solid ghost white)
    # Wide blade body, taper only at very tip, curved guard
    # -------------------------------------------------------
    # Sword proportions as fractions of size
    bw   = s * 0.12    # Blade full width (at crossguard)
    bcx  = s * 0.5     # Blade center X

    # Blade tip Y — near top of shield interior
    tip_y  = s * 0.26
    # Where taper starts (blade widens out from here)
    taper_y = s * 0.34
    # Bottom of blade (top of crossguard)
    blade_bottom_y = s * 0.62

    # Blade shape: tip → widen → full width → crossguard
    blade_pts = [
        (bcx,           tip_y),           # Pointed tip
        (bcx + bw/2,    taper_y),         # Start of full width right
        (bcx + bw/2,    blade_bottom_y),  # Bottom right of blade
        (bcx - bw/2,    blade_bottom_y),  # Bottom left of blade
        (bcx - bw/2,    taper_y),         # Start of full width left
    ]
    draw.polygon(blade_pts, fill=sword_color)

    # -------------------------------------------------------
    # CROSSGUARD — curved Norse bow shape
    # Wider than blade, curves up in the middle
    # -------------------------------------------------------
    gw = s * 0.38     # Guard total width
    gh = s * 0.05     # Guard height
    gy = blade_bottom_y  # Guard top Y

    # Draw crossguard as an ellipse (gives the curved bow effect)
    guard_bbox = [
        bcx - gw/2, gy - gh/2,
        bcx + gw/2, gy + gh/2
    ]
    draw.ellipse(guard_bbox, fill=sword_color)

    # -------------------------------------------------------
    # GRIP
    # -------------------------------------------------------
    grip_w = s * 0.09
    grip_h = s * 0.07
    grip_top = gy + gh/2

    draw.rounded_rectangle(
        [bcx - grip_w/2, grip_top,
         bcx + grip_w/2, grip_top + grip_h],
        radius=max(1, int(s * 0.015)),
        fill=sword_color
    )

    # -------------------------------------------------------
    # POMMEL — small flat ellipse
    # -------------------------------------------------------
    pm_w = s * 0.13
    pm_h = s * 0.05
    pm_top = grip_top + grip_h

    draw.ellipse(
        [bcx - pm_w/2, pm_top,
         bcx + pm_w/2, pm_top + pm_h],
        fill=sword_color
    )

    return img


def create_ico(output_path, dark_mode=True):
    """
    Creates a Windows .ico file containing the icon at all
    standard sizes required by Windows.

    Parameters:
        output_path (str) : Full path where the .ico file will be saved.
        dark_mode   (bool): True = dark theme icon (default for app).
    """
    # All sizes Windows uses for icons
    sizes = [16, 24, 32, 48, 64, 128, 256]

    images = []
    for size in sizes:
        img = draw_icon(size, dark_mode=dark_mode)
        images.append(img)

    # Save as .ico — Pillow handles the multi-size ICO format
    # The first image in the list is the primary (largest) icon
    images[0].save(
        output_path,
        format='ICO',
        sizes=[(s, s) for s in sizes],
        append_images=images[1:]
    )

    print(f"Icon saved: {output_path}")
    print(f"  Sizes: {', '.join(str(s) for s in sizes)}px")
    print(f"  Mode: {'Dark' if dark_mode else 'Light'}")


def main():
    """Generates both dark and light mode icons."""
    # Determine the assets directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    assets_dir = os.path.join(script_dir, 'assets')
    os.makedirs(assets_dir, exist_ok=True)

    # Generate dark mode icon (primary — used for the .exe)
    dark_ico_path = os.path.join(assets_dir, 'icon.ico')
    create_ico(dark_ico_path, dark_mode=True)

    # Generate light mode icon (alternate)
    light_ico_path = os.path.join(assets_dir, 'icon_light.ico')
    create_ico(light_ico_path, dark_mode=False)

    # Also save a PNG preview at 256px for reference
    preview = draw_icon(256, dark_mode=True)
    preview_path = os.path.join(assets_dir, 'icon_preview.png')
    preview.save(preview_path, format='PNG')
    print(f"\nPreview PNG: {preview_path}")

    print("\nIcon generation complete.")
    print("Next step: run PyInstaller to build the exe.")
    print("  pyinstaller SentinelHome101.spec")


if __name__ == "__main__":
    main()
