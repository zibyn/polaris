import { revalidateLogic, useForm } from "@tanstack/react-form";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CopyButton } from "#/components/copy-button";
import { FormError, FormField, saved } from "#/components/form";
import { Button } from "#/components/ui/button";
import { Field, FieldGroup, FieldLabel } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import { api, type ProviderInfo, type ProviderType } from "#/lib/console-api";
import { providerSchema } from "#/lib/login";
import { providersQuery } from "#/routes/console/providers/index";
import { date } from "#/routes/console/users/index";

// ProviderForm edits a Provider of type, or adds one without current. The
// ID and the type's immutable fields (the issuer) are set only when adding;
// a secret already set shows empty and stays unless retyped. onDone gets
// the saved Provider's ID, when the caller has somewhere to go. Editing,
// the ID and 回调 URL sit in the page header instead.
export function ProviderForm({
	type,
	current,
	editable = true,
	onDone,
	onCancel,
}: {
	type: ProviderType;
	current?: ProviderInfo;
	editable?: boolean;
	onDone?: (id: string) => void;
	onCancel?: () => void; // shown while adding, to close the drawer
}) {
	const client = useQueryClient();
	const fields = type.fields;
	const save = useMutation({
		mutationFn: (v: {
			id: string;
			name: string;
			config: Record<string, string>;
		}) =>
			current
				? api(`/providers/${encodeURIComponent(current.id)}`, {
						method: "PUT",
						body: { name: v.name, config: v.config },
					}).then(() => current.id)
				: api("/providers", {
						method: "POST",
						body: { ...v, type: type.key },
					}).then(() => v.id),
		// Await the new list before onDone navigates: the detail page's
		// loader reads the cache and would turn an unknown Provider away.
		onSuccess: async (id) => {
			await client.invalidateQueries(providersQuery);
			saved();
			onDone?.(id);
		},
	});
	const form = useForm({
		defaultValues: {
			id: current?.id ?? type.key,
			name: current?.name ?? "",
			config: Object.fromEntries(
				fields.map((f) => [
					f.key,
					f.secret ? "" : (current?.config[f.key] ?? ""),
				]),
			),
		},
		validationLogic: revalidateLogic(),
		validators: {
			onDynamic: providerSchema(fields, current?.secrets ?? {}, !current),
		},
		onSubmit: ({ value }) =>
			save.mutate({
				id: value.id.trim(),
				name: value.name.trim(),
				config: Object.fromEntries(
					Object.entries(value.config).map(([k, v]) => [k, v.trim()]),
				),
			}),
	});
	return (
		<form
			noValidate
			className="space-y-4"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			<FieldGroup className="gap-4">
				{!current && (
					<form.Field name="id">
						{(field) => (
							<FormField
								field={field}
								label="Provider ID"
								help="用于回调 URL，添加后不可修改。"
							>
								{(control) => (
									<Input
										{...control}
										className="w-64 font-mono"
										disabled={!editable}
										placeholder={type.key}
									/>
								)}
							</FormField>
						)}
					</form.Field>
				)}
				{!current && (
					<form.Subscribe selector={(s) => s.values.id}>
						{(id) => {
							const url = `${location.origin}/login/providers/${id.trim() || "{Provider ID}"}/callback`;
							return (
								<Field>
									<FieldLabel>回调 URL</FieldLabel>
									<div className="flex flex-wrap items-center gap-2">
										<span className="break-all font-mono text-sm">{url}</span>
										<CopyButton value={url} />
									</div>
									<p className="text-[13px] text-muted-foreground">
										在认证源后台中添加为回调地址。
									</p>
								</Field>
							);
						}}
					</form.Subscribe>
				)}
				<form.Field name="name">
					{(field) => (
						<FormField
							field={field}
							label="名称"
							help="登录页按钮显示为「使用 {名称} 登录」。"
						>
							{(control) => (
								<Input
									{...control}
									className="w-64"
									disabled={!editable}
									placeholder={type.name}
								/>
							)}
						</FormField>
					)}
				</form.Field>
				{fields.map((f) => {
					const setAt = current?.secrets[f.key];
					return (
						<form.Field key={f.key} name={`config.${f.key}`}>
							{(field) => (
								<FormField
									field={field}
									label={f.label}
									en={f.optional ? "选填" : undefined}
									help={
										f.immutable
											? `${f.help ? `${f.help}。` : ""}添加后不可修改。`
											: f.help
									}
								>
									{(control) => (
										<Input
											{...control}
											type={f.secret ? "password" : f.type}
											autoComplete={f.secret ? "new-password" : "off"}
											disabled={!editable || (!!current && f.immutable)}
											placeholder={
												setAt
													? `已设置 · 更新于 ${date(setAt)}，留空不修改`
													: ""
											}
										/>
									)}
								</FormField>
							)}
						</form.Field>
					);
				})}
			</FieldGroup>
			<FormError error={save.error} />
			<div className="flex gap-2">
				{editable && (
					<Button type="submit" disabled={save.isPending}>
						{current ? "保存" : "添加认证源"}
					</Button>
				)}
				{onCancel && (
					<Button type="button" variant="outline" onClick={onCancel}>
						取消
					</Button>
				)}
			</div>
		</form>
	);
}
