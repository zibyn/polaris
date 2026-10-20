import { createFileRoute } from "@tanstack/react-router";
import { type Header, useCan } from "#/routes/console/route";
import { CreateUserForm } from "./-components/create-user-form";

export const Route = createFileRoute("/console/users/new")({
	staticData: { crumb: "创建用户", useHeader },
	component: CreateUser,
});

// useHeader titles the page; without the Permission there's no header,
// only the note.
function useHeader(): Header | null {
	const can = useCan();
	if (!can("users:write")) {
		return null;
	}
	return {
		title: "创建用户",
		description:
			"建好的账号是待激活：本人能登录，但在自己设置密码之前拿不到任何令牌。",
	};
}

function CreateUser() {
	const can = useCan();
	if (!can("users:write")) {
		return <p className="text-sm">需要「管理员」角色才能创建用户。</p>;
	}
	return <CreateUserForm />;
}
