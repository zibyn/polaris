import { revalidateLogic, useForm } from "@tanstack/react-form";
import { useSuspenseQuery } from "@tanstack/react-query";
import { useState } from "react";
import { FormField } from "#/components/form";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Input } from "#/components/ui/input";
import { Switch } from "#/components/ui/switch";
import type { ChannelSettings, Policy } from "#/lib/console-api";
import {
	asksRequirePhone,
	asksTermsVersion,
	hasChannel,
	passwordLocksOut,
	termsSchema,
} from "#/lib/login";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { SaveBar, Section } from "#/routes/console/-components/section";
import { ChannelsLink, channelsQuery } from "./channels";
import { usePolicy, useSavePolicy } from "./policy";

const codeKinds = [
	{ kind: "phone", label: "手机号", channel: "短信" },
	{ kind: "email", label: "邮箱", channel: "邮件" },
] as const;

export function LoginTab() {
	const { policy, editable } = usePolicy();
	const { channels } = useSuspenseQuery(channelsQuery).data;
	const p = policy;
	const sms = hasChannel(channels, "phone");
	return (
		<div className="space-y-10">
			<CodeLogin channels={channels} />
			<OpenRegistration current={p} editable={editable} />
			<PasswordLogin current={p} editable={editable} />
			<PasskeyLogin current={p} editable={editable} />
			<RequirePhone current={p} editable={editable} sms={sms} />
			<Terms current={p} editable={editable} />
			<AdminsNeedTwoFactor current={p} editable={editable} />
		</div>
	);
}

// AdminsNeedTwoFactor: the server turns it down while the admin saving it
// has neither 两步验证 nor a Passkey of their own; SaveBar shows why.
function AdminsNeedTwoFactor({ current, editable }: SectionProps) {
	const save = useSavePolicy();
	const form = useForm({
		defaultValues: { adminsNeedTwoFactor: current.adminsNeedTwoFactor },
		onSubmit: ({ value }) => save.mutate(value),
	});
	return (
		<Section
			title="两步验证"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="adminsNeedTwoFactor">
				{(field) => (
					<FormField
						field={field}
						label="管理员必须启用两步验证或 Passkey"
						help="管理员账号被盗会暴露整个实例。开启后，既没开启两步验证也没有 Passkey 的管理员不能使用管理端，要先去账号中心开启或添加，也不能让两者一样都不剩。你自己要先满足其中一项。"
					>
						{({ id }) => (
							<Switch
								id={id}
								checked={field.state.value}
								disabled={!editable}
								onCheckedChange={field.handleChange}
							/>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}

type SectionProps = { current: Policy; editable: boolean };

function CodeLogin({ channels }: { channels: ChannelSettings[] }) {
	return (
		<section>
			<h2 className="font-semibold text-[15px]">验证码登录</h2>
			<div className="mt-4 space-y-3">
				{codeKinds.map((k) =>
					hasChannel(channels, k.kind) ? (
						<p key={k.kind} className="text-sm">
							用户可以用{k.label}收验证码登录。
						</p>
					) : (
						<Alert key={k.kind} variant="warning">
							<AlertDescription>
								没有启用{k.channel}通道，用户不能用{k.label}收验证码登录。{" "}
								<ChannelsLink />
							</AlertDescription>
						</Alert>
					),
				)}
			</div>
		</section>
	);
}

function OpenRegistration({ current, editable }: SectionProps) {
	const save = useSavePolicy();
	const form = useForm({
		defaultValues: { openRegistration: current.openRegistration },
		onSubmit: ({ value }) => save.mutate(value),
	});
	return (
		<Section
			title="开放注册"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="openRegistration">
				{(field) => (
					<FormField
						field={field}
						label="开放注册"
						help="陌生人用手机号、邮箱或外部账号第一次登录时，自动成为新用户。关闭后不再给没注册过的手机号或邮箱发验证码，没绑定过的外部账号也登录不了；已有用户照常登录，管理员仍可创建用户、发注册邀请。关闭后，登录页的提示会透露某个手机号或邮箱是否已注册。"
					>
						{({ id }) => (
							<Switch
								id={id}
								checked={field.state.value}
								disabled={!editable}
								onCheckedChange={field.handleChange}
							/>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}

function PasswordLogin({ current, editable }: SectionProps) {
	const save = useSavePolicy();
	const form = useForm({
		defaultValues: { passwordLogin: current.passwordLogin },
		onSubmit: ({ value }) => save.mutate(value),
	});
	return (
		<Section
			title="密码登录"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="passwordLogin">
				{(field) => (
					<FormField
						field={field}
						label="允许密码登录"
						help="用户可以用手机号、邮箱或用户名加密码登录。关闭后，已经设置的密码会保留，但不能用来登录。"
					>
						{({ id }) => (
							<>
								<Switch
									id={id}
									checked={field.state.value === "on"}
									disabled={!editable}
									onCheckedChange={(on) =>
										field.handleChange(on ? "on" : "off")
									}
								/>
								{passwordLocksOut(field.state.value) && (
									<Alert variant="warning">
										<AlertDescription>
											只用用户名登录的用户将无法登录，账号中心也不能设置密码。
										</AlertDescription>
									</Alert>
								)}
							</>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}

// PasskeyLogin: the server turns it down while the admin saving it satisfies
// 管理员必须启用两步验证或 Passkey with a Passkey alone; SaveBar shows why.
function PasskeyLogin({ current, editable }: SectionProps) {
	const save = useSavePolicy();
	const form = useForm({
		defaultValues: { passkeyLogin: current.passkeyLogin },
		onSubmit: ({ value }) => save.mutate(value),
	});
	return (
		<Section
			title="Passkey"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="passkeyLogin">
				{(field) => (
					<FormField
						field={field}
						label="允许 Passkey 登录"
						help="用户可以在设备或密码管理器里各存一把 Passkey，登录时不用等验证码。关闭后所有 Passkey 入口都会消失，已添加的 Passkey 会保留，重新打开后照常可用。"
					>
						{({ id }) => (
							<Switch
								id={id}
								checked={field.state.value}
								disabled={!editable}
								onCheckedChange={field.handleChange}
							/>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}

function RequirePhone({
	current,
	editable,
	sms,
}: SectionProps & { sms: boolean }) {
	const save = useSavePolicy();
	const [asking, setAsking] = useState(false);
	const form = useForm({
		defaultValues: { requirePhone: current.requirePhone },
		onSubmit: ({ value }) =>
			asksRequirePhone(current.requirePhone, value.requirePhone)
				? setAsking(true)
				: save.mutate(value),
	});
	return (
		<Section
			title="必须绑定手机号"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="requirePhone">
				{(field) => (
					<FormField
						field={field}
						label="必须绑定手机号"
						help="让每个用户都有手机号，方便找回账号和发通知。开启后，没有手机号的用户要先绑定才能登录。"
					>
						{({ id }) => (
							<>
								<Switch
									id={id}
									checked={field.state.value}
									// Without SMS it can only be turned off, never on.
									disabled={!editable || (!sms && !field.state.value)}
									onCheckedChange={field.handleChange}
								/>
								{!sms && (
									<Alert variant="warning">
										<AlertDescription>
											先启用短信通道。没有短信通道，用户收不到绑定手机号的验证码。{" "}
											<ChannelsLink>去启用短信通道</ChannelsLink>
										</AlertDescription>
									</Alert>
								)}
							</>
						)}
					</FormField>
				)}
			</form.Field>
			<ConfirmDialog
				open={asking}
				onOpenChange={setAsking}
				title="开启必须绑定手机号？"
				action="开启必须绑定手机号"
				destructive={false}
				onConfirm={() => save.mutate({ requirePhone: true })}
			>
				没有手机号的用户下次登录时要先绑定才能继续。
			</ConfirmDialog>
		</Section>
	);
}

function Terms({ current, editable }: SectionProps) {
	const save = useSavePolicy();
	const [pending, setPending] = useState<Partial<Policy>>();
	const form = useForm({
		defaultValues: {
			termsUrl: current.termsUrl,
			privacyUrl: current.privacyUrl,
			termsVersion: current.termsVersion,
		},
		validationLogic: revalidateLogic(),
		validators: { onDynamic: termsSchema },
		onSubmit: ({ value }) => {
			const t = {
				termsUrl: value.termsUrl.trim(),
				privacyUrl: value.privacyUrl.trim(),
				termsVersion: value.termsVersion.trim(),
			};
			if (asksTermsVersion(current.termsVersion, t.termsVersion)) {
				setPending(t);
			} else {
				save.mutate(t);
			}
		},
	});
	return (
		<Section
			title="用户协议"
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="termsUrl">
				{(field) => (
					<FormField field={field} label="用户协议地址">
						{(control) => (
							<Input
								{...control}
								type="url"
								placeholder="https://example.com/terms"
							/>
						)}
					</FormField>
				)}
			</form.Field>
			<form.Field name="privacyUrl">
				{(field) => (
					<FormField field={field} label="隐私政策地址">
						{(control) => (
							<Input
								{...control}
								type="url"
								placeholder="https://example.com/privacy"
							/>
						)}
					</FormField>
				)}
			</form.Field>
			<form.Field name="termsVersion">
				{(field) => (
					<FormField
						field={field}
						label="协议版本"
						help="用户登录时要勾选同意这一版协议。留空就不要求同意。"
					>
						{(control) => (
							<Input {...control} className="w-48" placeholder="如 2026-10" />
						)}
					</FormField>
				)}
			</form.Field>
			<ConfirmDialog
				open={!!pending}
				onOpenChange={(o) => !o && setPending(undefined)}
				title="更新协议版本？"
				action="更新协议版本"
				destructive={false}
				onConfirm={() => pending && save.mutate(pending)}
			>
				所有用户下次登录都要重新同意。接了直连认证 API 的 App 要带上新版本号。
			</ConfirmDialog>
		</Section>
	);
}
