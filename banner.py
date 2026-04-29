"""
JAXEN — recon platform banner.

    from banner import print_banner
    print_banner()                    # default 'shadow'
    print_banner(variant='wood')      # 3D wooden block (closer to the original western feel)
    print_banner(variant='wanted')    # slab-serif wanted-poster

CLI:    python3 banner.py [shadow|wood|wanted]
Honors NO_COLOR env var.
"""
import os
import re
import sys

# ── Palette ─────────────────────────────────────────────────────────────
# Warm tan matching the original; 24-bit truecolor (graceful in modern terms).
TAN     = "\033[38;2;200;144;96m"   # #c89060 — primary letterform
TAN_DIM = "\033[38;2;130;90;58m"    # #825a3a — cat / shadow / dim
DIM     = "\033[38;2;110;100;90m"   # subtle separator + metadata
RESET   = "\033[0m"
BOLD    = "\033[1m"

# ── Mascot ──────────────────────────────────────────────────────────────
# Sitting cat — alert, watching. 6 lines for shadow logo baseline match.
CAT = [
    r"   /\_/\   ",
    r"  ( o.o )  ",
    r"   > ^ <   ",
    r"  /     \  ",
    r" (   _   ) ",
    r"  ^^   ^^  ",
]

# ── Logo variants (line lists preserve all whitespace and special chars) ─

# ansi_shadow — clean modern blocks; J descender on lines 3-5.
LOGO_SHADOW = [
    "     ██╗ █████╗ ██╗  ██╗███████╗███╗   ██╗",
    "     ██║██╔══██╗╚██╗██╔╝██╔════╝████╗  ██║",
    "     ██║███████║ ╚███╔╝ █████╗  ██╔██╗ ██║",
    "██   ██║██╔══██║ ██╔██╗ ██╔══╝  ██║╚██╗██║",
    "╚█████╔╝██║  ██║██╔╝ ██╗███████╗██║ ╚████║",
    " ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝",
]

# larry3d — 3D wooden block; closest to the original's western character.
LOGO_WOOD = [
    r" _____  ______   __   __   ____    __  __     ",
    r"/\___ \/\  _  \ /\ \ /\ \ /\  _`\ /\ \/\ \    ",
    r"\/__/\ \ \ \L\ \\ `\`\/'/'\ \ \L\_\ \ `\\ \   ",
    r"   _\ \ \ \  __ \`\/ > <   \ \  _\L\ \ , ` \  ",
    r"  /\ \_\ \ \ \/\ \  \/'/\`\ \ \ \L\ \ \ \`\ \ ",
    "  \\ \\____/\\ \\_\\ \\_\\ /\\_\\\\ \\_\\\\ \\____/\\ \\_\\ \\_\\",
    r"   \/___/  \/_/\/_/ \/_/ \/_/ \/___/  \/_/\/_/",
]

# georgia11 — wanted-poster slab serif. Most thematically western.
LOGO_WANTED = [
    "   `7MMF'    db      `YMM'   `MP' `7MM\"\"\"YMM  `7MN.   `7MF'",
    "     MM     ;MM:       VMb.  ,P     MM    `7    MMN.    M  ",
    "     MM    ,V^MM.       `MM.M'      MM   d      M YMb   M  ",
    "     MM   ,M  `MM         MMb       MMmmMM      M  `MN. M  ",
    "     MM   AbmmmqMA      ,M'`Mb.     MM   Y  ,   M   `MM.M  ",
    "(O)  MM  A'     VML    ,P   `MM.    MM     ,M   M     YMM  ",
    " Ymmm9 .AMA.   .AMMA..MM:.  .:MMa..JMMmmmmMMM .JML.    YM  ",
]

VARIANTS = {"shadow": LOGO_SHADOW, "wood": LOGO_WOOD, "wanted": LOGO_WANTED}


def _pad_to_height(lines, height):
    """Pad to `height` rows by adding blanks top then bottom."""
    diff = height - len(lines)
    if diff <= 0:
        return lines[:height]
    width = max(len(l) for l in lines) if lines else 0
    blank = " " * width
    top = diff // 2
    return [blank] * top + lines + [blank] * (diff - top)


def render(variant="shadow", tagline="recon platform",
           version="v0.1.0", handle="@nuclide"):
    """Return the full colored banner as a single string."""
    logo = VARIANTS.get(variant, LOGO_SHADOW)
    height = max(len(CAT), len(logo))
    cat = _pad_to_height(CAT, height)
    logo = _pad_to_height(logo, height)

    cat_w = max(len(l) for l in cat)
    cat = [l.ljust(cat_w) for l in cat]
    logo_w = max(len(l) for l in logo)
    logo = [l.ljust(logo_w) for l in logo]

    out = [""]
    for c, l in zip(cat, logo):
        out.append(f"   {TAN_DIM}{c}{RESET}   {TAN}{BOLD}{l}{RESET}")

    indent = "   " + " " * cat_w + "   "
    sep = "─" * 4
    meta = f"{sep}  {tagline} · {version} · {handle}  {sep}"
    pad_l = max(0, (logo_w - len(meta)) // 2)
    out.append("")
    out.append(f"{indent}{' ' * pad_l}{DIM}{meta}{RESET}")
    out.append("")
    return "\n".join(out)


def print_banner(variant="shadow", **kw):
    """Print the banner. Strips ANSI when NO_COLOR is set."""
    s = render(variant, **kw)
    if os.environ.get("NO_COLOR"):
        s = re.sub(r"\033\[[0-9;]*m", "", s)
    print(s)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "shadow"
    if v not in VARIANTS:
        print(f"unknown variant: {v}. choices: {', '.join(VARIANTS)}", file=sys.stderr)
        sys.exit(2)
    print_banner(v)
