import { z } from "zod";

// contrastOnWhite is WCAG 2's contrast ratio of #rrggbb against white: how
// white text reads on it, and it on a white page.
export function contrastOnWhite(hex: string): number {
	const n = Number.parseInt(hex.slice(1), 16);
	const lin = (c: number) => {
		const v = c / 255;
		return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
	};
	const l =
		0.2126 * lin((n >> 16) & 0xff) +
		0.7152 * lin((n >> 8) & 0xff) +
		0.0722 * lin(n & 0xff);
	return 1.05 / (l + 0.05);
}

// brandSchema stops a 品牌 save the backend would reject: a name of at
// most 64 characters, and a primary colour as #rrggbb that white text reads
// on at 4.5:1 (WCAG AA). Both may be empty.
export const brandSchema = z.object({
	name: z.string().trim().max(64, "品牌名最多 64 个字符。"),
	color: z
		.string()
		.trim()
		.refine((c) => c === "" || /^#[0-9a-fA-F]{6}$/.test(c), {
			message: "请填写 #rrggbb 格式的颜色，如 #0A66C2。",
		})
		.refine((c) => !/^#[0-9a-fA-F]{6}$/.test(c) || contrastOnWhite(c) >= 4.5, {
			message: "请换深一些的颜色：白字放在上面要看得清，对比度要达到 4.5:1。",
		}),
});

// logoProblem is why a picked file cannot be a Logo, or undefined; the
// server judges the bytes, this only spares an upload doomed by its type or
// size.
export function logoProblem(file: {
	size: number;
	type: string;
}): string | undefined {
	if (!["image/png", "image/webp", "image/svg+xml"].includes(file.type)) {
		return "Logo 须为 PNG、WebP 或 SVG 图片";
	}
	if (file.size > 1 << 20) return "Logo 不能超过 1 MB";
}
