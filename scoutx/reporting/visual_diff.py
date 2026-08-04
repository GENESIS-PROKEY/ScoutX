import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

logger = logging.getLogger("scoutx.reporting.visual_diff")

try:
    from PIL import Image, ImageChops
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False


@dataclass
class DiffItem:
    hostname: str
    status: str  # 'new', 'removed', 'changed', 'unchanged'
    img1_path: Path | None
    img2_path: Path | None
    diff_img_path: Path | None
    change_percent: float


class VisualDiffGenerator:
    """Generate visual diffs of screenshots between two scans."""

    def __init__(self) -> None:
        self.items: List[DiffItem] = []

    async def generate(self, dir1: Path, dir2: Path, output_dir: Path) -> Path:
        if not HAS_PILLOW:
            logger.warning("Pillow is not installed. Visual diffing will be skipped.")
            return output_dir

        screenshots1_dir = dir1 / "screenshots"
        screenshots2_dir = dir2 / "screenshots"

        diff_out_dir = output_dir / "visual_diff"
        diff_out_dir.mkdir(parents=True, exist_ok=True)

        imgs1 = {}
        if screenshots1_dir.exists():
            for p in screenshots1_dir.glob("*.png"):
                imgs1[p.stem] = p

        imgs2 = {}
        if screenshots2_dir.exists():
            for p in screenshots2_dir.glob("*.png"):
                imgs2[p.stem] = p

        all_hosts = set(imgs1.keys()) | set(imgs2.keys())

        for host in sorted(all_hosts):
            p1 = imgs1.get(host)
            p2 = imgs2.get(host)

            if p1 and not p2:
                self.items.append(DiffItem(host, "removed", p1, None, None, 0.0))
            elif p2 and not p1:
                self.items.append(DiffItem(host, "new", None, p2, None, 0.0))
            elif p1 and p2:
                diff_path = diff_out_dir / f"{host}_diff.png"
                change_pct = self._generate_diff_image(p1, p2, diff_path)
                status = "changed" if change_pct > 0 else "unchanged"
                self.items.append(DiffItem(host, status, p1, p2, diff_path, change_pct))

        report_path = diff_out_dir / "visual_diff.html"
        self._generate_html_report(report_path)
        return report_path

    def _generate_diff_image(self, p1: Path, p2: Path, out: Path) -> float:
        with Image.open(p1) as img1_orig, Image.open(p2) as img2_orig:
            img1 = img1_orig.convert("RGBA")
            img2 = img2_orig.convert("RGBA")

            if img1.size != img2.size:
                max_w = max(img1.size[0], img2.size[0])
                max_h = max(img1.size[1], img2.size[1])

                new_img1 = Image.new("RGBA", (max_w, max_h), (255, 255, 255, 255))
                new_img1.paste(img1, (0, 0))
                img1 = new_img1

                new_img2 = Image.new("RGBA", (max_w, max_h), (255, 255, 255, 255))
                new_img2.paste(img2, (0, 0))
                img2 = new_img2

            diff = ImageChops.difference(img1.convert("RGB"), img2.convert("RGB"))

            diff_mask = diff.convert("L").point(lambda x: 255 if x > 0 else 0)

            changed_pixels = 0
            for pixel in diff_mask.getdata():
                if pixel > 0:
                    changed_pixels += 1

            total_pixels = img1.size[0] * img1.size[1]
            change_percent = (changed_pixels / total_pixels) * 100 if total_pixels > 0 else 0.0

            if changed_pixels > 0:
                red_overlay = Image.new("RGBA", img2.size, (255, 0, 0, 128))
                red_mask = Image.new("RGBA", img2.size, (0, 0, 0, 0))
                red_mask.paste(red_overlay, (0, 0), diff_mask)

                result_img = Image.alpha_composite(img2, red_mask)
                result_img.save(out, "PNG")
            else:
                img2.save(out, "PNG")

            return change_percent

    def _generate_html_report(self, out_path: Path) -> None:
        html = ["<html><head><title>Visual Diff Report</title><style>"]
        html.append("body { font-family: sans-serif; background: #111; color: #eee; }")
        html.append(".row { display: flex; flex-direction: row; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 10px; }")
        html.append(".col { flex: 1; padding: 10px; text-align: center; }")
        html.append("img { max-width: 100%; border: 1px solid #444; }")
        html.append(".significant { color: #ff5555; font-weight: bold; }")
        html.append("</style></head><body>")
        html.append("<h1>ScoutX Visual Diff Report</h1>")

        for item in self.items:
            html.append(f"<h2>Host: {item.hostname} - Status: {item.status.upper()}</h2>")

            if item.status == "changed":
                sig = "significant" if item.change_percent > 10.0 else ""
                html.append(f"<p class='{sig}'>Pixels changed: {item.change_percent:.2f}%</p>")

            html.append("<div class='row'>")

            html.append("<div class='col'><h3>Old</h3>")
            if item.img1_path:
                html.append(f"<img src='file://{item.img1_path.absolute().as_posix()}'/>")
            else:
                html.append("<p>No old image</p>")
            html.append("</div>")

            html.append("<div class='col'><h3>Diff</h3>")
            if item.diff_img_path:
                html.append(f"<img src='file://{item.diff_img_path.absolute().as_posix()}'/>")
            else:
                html.append("<p>No diff available</p>")
            html.append("</div>")

            html.append("<div class='col'><h3>New</h3>")
            if item.img2_path:
                html.append(f"<img src='file://{item.img2_path.absolute().as_posix()}'/>")
            else:
                html.append("<p>No new image</p>")
            html.append("</div>")

            html.append("</div>")

        html.append("</body></html>")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
