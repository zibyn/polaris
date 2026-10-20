import { revalidateLogic, useForm, useStore } from "@tanstack/react-form";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { FormError, FormField } from "#/components/form";
import { Button } from "#/components/ui/button";
import { FieldSet } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { api, type UserDetail } from "#/lib/console-api";
import { createUserSchema, type WayIn, wayName, waysIn } from "#/lib/users";
import { FormSheet } from "#/routes/console/-components/form-sheet";
import { PasswordLoginNotice, usePasswordLoginOff } from "./password-login";

// wayHelp is what each way in is, said under the choice.
const wayHelp: Record<WayIn, string> = {
	password:
		"当面或另找渠道把临时密码交给本人，对方第一次登录时必须先改成自己的密码。",
	invite:
		"认证服务往这个邮箱发一条 7 天有效的一次性链接，本人点开自己设密码，密码不经过你手上。",
};

// CreateUserForm opens one 待激活 account for an admin to hand over
// (ADR 0016), either with an initial password they pass on themselves or
// with a 注册邀请 that lets the User set their own. It is the page's form
// and the users list's drawer, so the two cannot drift.
export function CreateUserForm() {
	const off = usePasswordLoginOff();
	const client = useQueryClient();
	const navigate = useNavigate();
	const save = useMutation({
		mutationFn: (v: { identifier: string; way: WayIn; password: string }) =>
			api<UserDetail>("/users", {
				method: "POST",
				body:
					v.way === "invite"
						? { identifier: v.identifier.trim(), invite: true }
						: { identifier: v.identifier.trim(), password: v.password },
			}),
		onSuccess: async (user) => {
			await client.invalidateQueries({ queryKey: ["users"] });
			navigate({ to: "/console/users/$sub", params: { sub: user.sub } });
		},
	});
	const form = useForm({
		defaultValues: { identifier: "", way: "password" as WayIn, password: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: createUserSchema },
		onSubmit: ({ value }) => save.mutate(value),
	});
	const way = useStore(form.store, (s) => s.values.way);
	return (
		<form
			noValidate
			className="flex flex-col gap-6"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			{off && (
				<PasswordLoginNotice detail="关闭时建出来的账号没有可用的登录方式，本人进不来。" />
			)}
			<FieldSet disabled={off} className="gap-6">
				<form.Field name="way">
					{(field) => (
						<FormField
							field={field}
							label="怎么把账号交给本人"
							help={wayHelp[way]}
						>
							{({ id, "aria-invalid": invalid }) => (
								<Select
									value={field.state.value}
									onValueChange={(v) => field.handleChange(v as WayIn)}
								>
									<SelectTrigger
										id={id}
										aria-invalid={invalid}
										className="w-full"
									>
										<SelectValue>{(v: WayIn) => wayName[v]}</SelectValue>
									</SelectTrigger>
									<SelectContent>
										{waysIn.map((w) => (
											<SelectItem key={w} value={w}>
												{wayName[w]}
											</SelectItem>
										))}
									</SelectContent>
								</Select>
							)}
						</FormField>
					)}
				</form.Field>
				<form.Field name="identifier">
					{(field) => (
						<FormField
							field={field}
							label="登录标识"
							help={
								way === "invite"
									? "邀请只发到邮箱，所以这里要填邮箱地址。填的邮箱直接算已验证，不发验证邮件、也不消耗验证码条数。"
									: "手机号、邮箱或用户名。这里填的邮箱和手机号直接算已验证，认证服务不会给本人发验证邮件，也不消耗验证码条数。"
							}
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
				{way === "password" && (
					<form.Field name="password">
						{(field) => (
							<FormField field={field} label="初始密码" help={wayHelp.password}>
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
				)}
			</FieldSet>
			<FormError error={save.error} />
			<Button
				type="submit"
				disabled={save.isPending || off}
				className="self-start"
			>
				创建用户
			</Button>
		</form>
	);
}

// CreateUserSheet is 创建用户 over the list, so the filters and the rows
// stay in view while the admin fills the form in.
export function CreateUserSheet({
	open,
	onOpenChange,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
}) {
	return (
		<FormSheet
			open={open}
			onOpenChange={onOpenChange}
			title="创建用户"
			description="建好的账号是待激活：本人能登录，但在自己设置密码之前拿不到任何令牌。"
		>
			<CreateUserForm />
		</FormSheet>
	);
}
