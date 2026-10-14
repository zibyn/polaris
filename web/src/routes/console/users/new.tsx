import { revalidateLogic, useForm } from "@tanstack/react-form";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { FormError, FormField } from "#/components/form";
import { Button } from "#/components/ui/button";
import { FieldSet } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import { api, type UserDetail } from "#/lib/console-api";
import { createUserSchema } from "#/lib/users";
import { type Header, useCan } from "#/routes/console/route";
import {
	PasswordLoginNotice,
	usePasswordLoginOff,
} from "#/routes/console/users/index";

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

// CreateUser opens one 待激活 account for an admin to hand over (ADR 0016),
// with the initial password they pass on themselves.
function CreateUser() {
	const can = useCan();
	if (!can("users:write")) {
		return <p className="text-sm">需要「管理员」角色才能创建用户。</p>;
	}
	return <CreateForm />;
}

function CreateForm() {
	const off = usePasswordLoginOff();
	const client = useQueryClient();
	const navigate = useNavigate();
	const save = useMutation({
		mutationFn: (v: { identifier: string; password: string }) =>
			api<UserDetail>("/users", {
				method: "POST",
				body: { identifier: v.identifier.trim(), password: v.password },
			}),
		onSuccess: async (user) => {
			await client.invalidateQueries({ queryKey: ["users"] });
			navigate({ to: "/console/users/$sub", params: { sub: user.sub } });
		},
	});
	const form = useForm({
		defaultValues: { identifier: "", password: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: createUserSchema },
		onSubmit: ({ value }) => save.mutate(value),
	});
	return (
		<form
			noValidate
			className="max-w-3xl space-y-6"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			{off && (
				<PasswordLoginNotice detail="关闭时建出来的账号没有可用的登录方式，本人进不来。" />
			)}
			<FieldSet disabled={off} className="gap-6">
				<form.Field name="identifier">
					{(field) => (
						<FormField
							field={field}
							label="登录标识"
							help="手机号、邮箱或用户名。这里填的邮箱和手机号直接算已验证，认证服务不会给本人发验证邮件，也不消耗验证码条数。"
						>
							{(control) => (
								<Input
									{...control}
									autoComplete="off"
									placeholder="如 alice@example.com"
								/>
							)}
						</FormField>
					)}
				</form.Field>
				<form.Field name="password">
					{(field) => (
						<FormField
							field={field}
							label="初始密码"
							help="当面或另找渠道交给本人的临时密码，至少 8 位。对方第一次登录时，必须先把它改成自己的密码。"
						>
							{(control) => (
								<Input
									{...control}
									type="password"
									autoComplete="new-password"
								/>
							)}
						</FormField>
					)}
				</form.Field>
			</FieldSet>
			<FormError error={save.error} />
			<Button type="submit" disabled={save.isPending || off}>
				创建用户
			</Button>
		</form>
	);
}
