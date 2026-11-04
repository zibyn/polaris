import assert from "node:assert/strict";
import { test } from "node:test";
import { brandSchema, contrastOnWhite, logoProblem } from "./brand.ts";

const errors = (r: {
	error?: { issues: { path: PropertyKey[]; message: string }[] };
}) =>
	Object.fromEntries(
		(r.error?.issues ?? []).map((i) => [i.path.join("."), i.message]),
	);

test("contrast against white matches WCAG", () => {
	assert.equal(contrastOnWhite("#000000").toFixed(1), "21.0");
	assert.equal(contrastOnWhite("#FFFFFF").toFixed(1), "1.0");
	assert.ok(contrastOnWhite("#767676") >= 4.5);
	assert.ok(contrastOnWhite("#777777") < 4.5);
});

test("a dark enough #rrggbb, or none, saves", () => {
	for (const color of ["", "#0A66C2", "#7048e8"]) {
		assert.equal(brandSchema.safeParse({ name: "Acme", color }).success, true);
	}
});

test("a light colour or one not #rrggbb doesn't save", () => {
	assert.deepEqual(
		errors(brandSchema.safeParse({ name: "", color: "#ffff00" })),
		{
			color: "颜色过浅，与白色文字的对比度需不低于 4.5:1。",
		},
	);
	assert.deepEqual(errors(brandSchema.safeParse({ name: "", color: "blue" })), {
		color: "请输入 #rrggbb 格式的颜色，如 #0A66C2。",
	});
});

test("a Logo is a PNG, WebP or SVG of at most 1 MB", () => {
	assert.equal(logoProblem({ type: "image/svg+xml", size: 1000 }), undefined);
	assert.equal(
		logoProblem({ type: "image/jpeg", size: 1000 }),
		"Logo 须为 PNG、WebP 或 SVG 图片",
	);
	assert.equal(
		logoProblem({ type: "image/png", size: 2 << 20 }),
		"Logo 不能超过 1 MB",
	);
});
