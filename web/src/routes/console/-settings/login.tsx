import { revalidateLogic, useForm } from "@tanstack/react-form";
import { useIsMutating, useSuspenseQuery } from "@tanstack/react-query";
import { type ReactNode, useId, useState } from "react";
import { FormError, FormField } from "#/components/form";
import { ItemList, PropRow } from "#/components/item-list";
import { Alert, AlertDescription } from "#/components/ui/alert";
import {
	Field,
	FieldContent,
	FieldDescription,
	FieldLabel,
} from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import { Switch } from "#/components/ui/switch";
import type { ChannelSettings, Policy } from "#/lib/console-api";
import { hasChannel, planPolicySave, termsSchema } from "#/lib/login";
import { channelsQuery, settingsKey, useSavePolicy } from "#/lib/queries";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { SaveBar, Section } from "#/routes/console/-components/section";
import { ChannelsLink } from "./channels";
import { usePolicy } from "./policy";

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
			<Switches current={p} editable={editable} sms={sms} />
			<Terms current={p} editable={editable} />
		</div>
	);
}

type SectionProps = { current: Policy; editable: boolean };

function CodeLogin({ channels }: { channels: ChannelSettings[] }) {
	return (
		<Section title="验证码登录">
			<ItemList>
				{codeKinds.map((k) =>
					hasChannel(channels, k.kind) ? (
						<PropRow key={k.kind} label={k.label}>
							<span className="text-sm">用户可用{k.label}验证码登录。</span>
						</PropRow>
					) : (
						<PropRow
							key={k.kind}
							label={k.label}
							actions={
								<ChannelsLink>
									<span className="font-medium text-[13px] text-primary-ink underline-offset-2 hover:underline">
										设置验证码通道
									</span>
								</ChannelsLink>
							}
						>
							<span className="text-sm text-warning-foreground">
								未启用{k.channel}通道，用户无法使用{k.label}验证码登录。
							</span>
						</PropRow>
					),
				)}
			</ItemList>
		</Section>
	);
}

// Switches is every 登录方式 on/off: each saves the moment it flips, as
// switches do; a flip with consequences asks first (planPolicySave).
// The server turns some flips down while the admin saving them would lose
// their own way in (两步验证, Passkey, 密码); the row shows why.
function Switches({ current, editable, sms }: SectionProps & { sms: boolean }) {
	return (
		<>
			<Section title="注册与登录">
				<div className="space-y-6">
					<PolicySwitch
						current={current}
						editable={editable}
						label="开放注册"
						help="开启后，未注册的手机号、邮箱或外部账号首次登录时自动注册。关闭后，登录页会提示手机号或邮箱是否已注册。"
						checked={current.openRegistration}
						patch={(on) => ({ openRegistration: on })}
					/>
					<PolicySwitch
						current={current}
						editable={editable}
						label="允许密码登录"
						help="开启后，用户可用手机号、邮箱或用户名加密码登录。关闭后已设置的密码保留。"
						checked={current.passwordLogin === "on"}
						patch={(on) => ({ passwordLogin: on ? "on" : "off" })}
					>
						{planPolicySave(current, {}).warn.passwordLocksOut && (
							<Alert variant="warning">
								<AlertDescription>
									仅有用户名的用户将无法登录，也无法在账号中心设置密码。
								</AlertDescription>
							</Alert>
						)}
					</PolicySwitch>
					<PolicySwitch
						current={current}
						editable={editable}
						label="允许 Passkey 登录"
						help="开启后，用户可用 Passkey 登录。关闭后已添加的 Passkey 保留。"
						checked={current.passkeyLogin}
						patch={(on) => ({ passkeyLogin: on })}
					/>
					<PolicySwitch
						current={current}
						editable={editable}
						label="必须绑定手机号"
						help="开启后，没有手机号的用户需先绑定手机号才能登录。"
						checked={current.requirePhone}
						// Without SMS it can only be turned off, never on.
						disabled={!sms && !current.requirePhone}
						patch={(on) => ({ requirePhone: on })}
						confirm={{
							title: "开启必须绑定手机号？",
							action: "开启必须绑定手机号",
							body: "没有手机号的用户下次登录时需先绑定手机号。",
						}}
					>
						{!sms && (
							<Alert variant="warning">
								<AlertDescription>
									需先启用短信通道，否则用户收不到绑定手机号的验证码。{" "}
									<ChannelsLink>启用短信通道</ChannelsLink>
								</AlertDescription>
							</Alert>
						)}
					</PolicySwitch>
				</div>
			</Section>
			<Section title="管理员">
				<PolicySwitch
					current={current}
					editable={editable}
					label="管理员必须启用两步验证或 Passkey"
					help="开启后，未启用两步验证且没有 Passkey 的管理员无法使用管理端。"
					checked={current.adminsNeedTwoFactor}
					patch={(on) => ({ adminsNeedTwoFactor: on })}
				/>
			</Section>
		</>
	);
}

// PolicySwitch is one row of Switches: what it does on the left, the
// switch on the right, then any notes and why the last save failed.
function PolicySwitch({
	current,
	editable,
	label,
	help,
	checked,
	disabled,
	patch,
	confirm,
	children,
}: SectionProps & {
	label: string;
	help: ReactNode;
	checked: boolean;
	disabled?: boolean;
	patch: (on: boolean) => Partial<Policy>;
	confirm?: { title: string; action: string; body: ReactNode };
	children?: ReactNode;
}) {
	const id = useId();
	const save = useSavePolicy();
	// PUT /settings takes the whole Policy, so one save at a time: a second
	// flip mid-save would send the first one's old value back.
	const busy = useIsMutating({ mutationKey: settingsKey }) > 0;
	// want is where the switch is headed while its save is in flight.
	const [want, setWant] = useState<boolean>();
	const [asking, setAsking] = useState<boolean>();
	const go = (on: boolean) => {
		setWant(on);
		save.mutate(patch(on), { onSettled: () => setWant(undefined) });
	};
	return (
		<div className="space-y-3">
			<Field orientation="horizontal">
				<FieldContent>
					<FieldLabel htmlFor={id}>{label}</FieldLabel>
					<FieldDescription>{help}</FieldDescription>
				</FieldContent>
				<Switch
					id={id}
					checked={want ?? checked}
					disabled={!editable || busy || disabled}
					onCheckedChange={(on) =>
						confirm && planPolicySave(current, patch(on)).confirm
							? setAsking(on)
							: go(on)
					}
				/>
			</Field>
			{children}
			<FormError error={save.error} />
			{confirm && (
				<ConfirmDialog
					open={asking !== undefined}
					onOpenChange={(o) => !o && setAsking(undefined)}
					title={confirm.title}
					action={confirm.action}
					destructive={false}
					onConfirm={() => asking !== undefined && go(asking)}
				>
					{confirm.body}
				</ConfirmDialog>
			)}
		</div>
	);
}

function Terms({ current, editable }: SectionProps) {
	const save = useSavePolicy();
	const [pending, setPending] = useState<Partial<Policy>>();
	const form = useForm({
		defaultValues: {
			termsUrl: current.termsUrl,
			privacyUrl: current.privacyUrl,
			termsUrlEn: current.termsUrlEn ?? "",
			privacyUrlEn: current.privacyUrlEn ?? "",
			termsVersion: current.termsVersion,
		},
		validationLogic: revalidateLogic(),
		validators: { onDynamic: termsSchema },
		onSubmit: ({ value }) => {
			const t = {
				termsUrl: value.termsUrl.trim(),
				privacyUrl: value.privacyUrl.trim(),
				termsUrlEn: value.termsUrlEn.trim(),
				privacyUrlEn: value.privacyUrlEn.trim(),
				termsVersion: value.termsVersion.trim(),
			};
			if (planPolicySave(current, t).confirm) {
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
			<form.Field name="termsUrlEn">
				{(field) => (
					<FormField
						field={field}
						label="英文用户协议地址"
						help="用于英文登录页，留空则使用中文地址。"
					>
						{(control) => (
							<Input
								{...control}
								type="url"
								placeholder="https://example.com/en/terms"
							/>
						)}
					</FormField>
				)}
			</form.Field>
			<form.Field name="privacyUrlEn">
				{(field) => (
					<FormField
						field={field}
						label="英文隐私政策地址"
						help="用于英文登录页，留空则使用中文地址。"
					>
						{(control) => (
							<Input
								{...control}
								type="url"
								placeholder="https://example.com/en/privacy"
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
						help="用户登录时需同意该版本协议，留空则不要求。"
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
				所有用户下次登录时需重新同意，中英文协议共用此版本。使用直连认证 API
				的应用需传入新版本号。
			</ConfirmDialog>
		</Section>
	);
}
