import assert from "node:assert/strict";
import { test } from "node:test";
import { checklist, checklistDone, checklistSummary } from "./overview.ts";

const owner = ["users:read", "applications:read", "config:read"];
const builtinOnly = [{ builtin: true }];
const own = [{ builtin: true }, { builtin: false }];
const fresh = { channels: [], apps: builtinOnly, apis: builtinOnly };

const state = (steps: ReturnType<typeof checklist>) =>
	steps?.map((s) => [s.label, s.done]);

test("a fresh install lists all three steps undone, in order", () => {
	assert.deepEqual(state(checklist(owner, fresh)), [
		["配置通道", false],
		["创建应用", false],
		["添加 API 资源", false],
	]);
});

test("a step is done once its first own object exists", () => {
	assert.deepEqual(
		state(
			checklist(owner, {
				channels: [{ kind: "email" }],
				apps: own,
				apis: builtinOnly,
			}),
		),
		[
			["配置通道", true],
			["创建应用", true],
			["添加 API 资源", false],
		],
	);
});

test("steps the admin lacks the Permission for aren't listed", () => {
	assert.deepEqual(state(checklist(["config:read"], { channels: [] })), [
		["配置通道", false],
	]);
	assert.deepEqual(
		state(checklist(["applications:read"], { apps: own, apis: builtinOnly })),
		[
			["创建应用", true],
			["添加 API 资源", false],
		],
	);
	assert.deepEqual(state(checklist(["users:read"], {})), []);
});

test("nothing is listed while a visible step's data is loading", () => {
	assert.equal(checklist(owner, { channels: [], apps: own }), undefined);
});

const done = { channels: [{ kind: "phone" as const }], apps: own, apis: own };

test("each step is judged on its own data", () => {
	assert.deepEqual(
		state(checklist(owner, { channels: [], apps: [], apis: own })),
		[
			["配置通道", false],
			["创建应用", false],
			["添加 API 资源", true],
		],
	);
});

test("a checklist with every step done is done for good", () => {
	// The page remembers it, so undoing a step later doesn't bring it back.
	assert.equal(checklistDone(checklist(owner, done)), true);
});

test("a checklist with a step left, loading or empty isn't done", () => {
	assert.equal(checklistDone(checklist(owner, fresh)), false);
	assert.equal(checklistDone(checklist(owner, {})), false);
	assert.equal(checklistDone(checklist(["users:read"], {})), false);
});

test("the summary counts what's done and points at the first step left", () => {
	const s = checklistSummary(
		checklist(owner, {
			channels: [{ kind: "email" }],
			apps: builtinOnly,
			apis: own,
		}),
	);
	assert.equal(s?.done, 2);
	assert.equal(s?.total, 3);
	assert.equal(s?.title, "还差 1 步完成配置");
	assert.equal(s?.next.label, "创建应用");
	assert.equal(s?.next.to, "/console/apps");
	assert.match(s?.next.hint ?? "", /^下一步：/);
});

test("a finished or loading checklist has no summary", () => {
	assert.equal(checklistSummary(checklist(owner, done)), undefined);
	// Done counts only the steps the admin can see.
	assert.equal(
		checklistSummary(checklist(["config:read"], { channels: done.channels })),
		undefined,
	);
	assert.equal(checklistSummary(checklist(owner, {})), undefined);
});

test("a fresh setup starts at the 通道 tab of 设置", () => {
	const s = checklistSummary(checklist(owner, fresh));
	assert.equal(s?.next.label, "配置通道");
	assert.equal(s?.next.to, "/console/settings");
	assert.deepEqual(s?.next.search, { tab: "channels" });
});
