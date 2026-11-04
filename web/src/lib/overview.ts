// The overview's 上手清单 (docs/spec/consoles.md「概览」). Pure TypeScript:
// tested with node --test.
import { onlyBuiltin } from "./apps.ts";
import type { Application, ChannelSettings } from "./console-api.ts";

type Builtin = Pick<Application, "builtin">;

// checklist lists the steps of a first setup the admin can see, with
// whether each is done: a channel enabled, then an Application and an API
// resource of their own. Undefined while a visible step's data is loading.
export const checklist = (
	permissions: readonly string[],
	data: {
		channels?: Pick<ChannelSettings, "kind">[];
		apps?: Builtin[];
		apis?: Builtin[];
	},
) => {
	const steps = [
		{
			label: "配置通道",
			hint: "下一步：配置验证码通道，用于发送登录验证码。",
			to: "/console/settings",
			search: { tab: "channels" },
			permission: "config:read",
			done: data.channels && data.channels.length > 0,
		},
		{
			label: "创建应用",
			hint: "下一步：创建应用，接入登录。",
			to: "/console/apps",
			permission: "applications:read",
			done: data.apps && !onlyBuiltin(data.apps),
		},
		{
			label: "添加 API 资源",
			hint: "下一步：添加 API 资源，用于签发访问后端的令牌。",
			to: "/console/apis",
			permission: "applications:read",
			done: data.apis && !onlyBuiltin(data.apis),
		},
	] as const;
	const visible = steps.filter((s) => permissions.includes(s.permission));
	return visible.every((s) => s.done !== undefined)
		? visible.map((s) => ({ ...s, done: !!s.done }))
		: undefined;
};

// checklistDone: every visible step is done. The page then remembers the
// checklist as closed: it is one-off onboarding, not an ongoing health
// check, so undoing a step later doesn't bring it back.
export const checklistDone = (steps: ReturnType<typeof checklist>) =>
	!!steps?.length && steps.every((s) => s.done);

// checklistSummary is what the checklist block shows: progress and the
// first step left. Undefined once nothing is left or while loading.
export const checklistSummary = (steps: ReturnType<typeof checklist>) => {
	const next = steps?.find((s) => !s.done);
	if (!steps || !next) {
		return undefined;
	}
	const done = steps.filter((s) => s.done).length;
	const left = steps.length - done;
	return {
		done,
		total: steps.length,
		title: `还差 ${left} 步完成配置`,
		next,
	};
};
