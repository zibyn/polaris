import { revalidateLogic, useForm } from "@tanstack/react-form";
import { useState } from "react";
import { FormField } from "#/components/form";
import { Input } from "#/components/ui/input";
import type { Policy } from "#/lib/console-api";
import { planPolicySave, termsSchema } from "#/lib/login";
import { useSavePolicy } from "#/lib/queries";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { SaveBar, Section } from "#/routes/console/-components/section";
import { usePolicy } from "./policy";

export function TermsTab() {
	const { policy, editable } = usePolicy();
	return <Terms current={policy} editable={editable} />;
}

function Terms({ current, editable }: { current: Policy; editable: boolean }) {
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
