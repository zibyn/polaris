import assert from "node:assert/strict";
import { test } from "node:test";
import { deviceLabel } from "./device.ts";

test("a browser reads as browser · system", () => {
	const cases: [string, string][] = [
		[
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			"Chrome · macOS",
		],
		[
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
			"Edge · Windows",
		],
		[
			"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
			"Firefox · Linux",
		],
		[
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			"Safari · iOS",
		],
		[
			"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
			"Chrome · Android",
		],
	];
	for (const [ua, want] of cases) assert.equal(deviceLabel(ua), want, ua);
});

test("the Polaris KMP SDK reads as model · system version", () => {
	assert.equal(
		deviceLabel("Notes/2.1.0 (Android 14; Pixel 8) Polaris-KMP/0.3.0"),
		"Pixel 8 · Android 14",
	);
	assert.equal(
		deviceLabel("Notes/2.1.0 (iOS 17.5; iPhone15,2) Polaris-KMP/0.3.0"),
		"iPhone15,2 · iOS 17.5",
	);
});

test("an unknown User-Agent shows cut short, none at all as 未知设备", () => {
	assert.equal(deviceLabel("curl/8.5.0"), "curl/8.5.0");
	assert.equal(deviceLabel(`okhttp/${"9".repeat(80)}`).length, 41);
	assert.ok(deviceLabel(`okhttp/${"9".repeat(80)}`).endsWith("…"));
	assert.equal(deviceLabel(undefined), "未知设备");
	assert.equal(deviceLabel(""), "未知设备");
});
