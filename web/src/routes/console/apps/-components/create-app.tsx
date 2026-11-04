import { revalidateLogic, useForm } from "@tanstack/react-form";
import {
	useMutation,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ChevronRightIcon } from "lucide-react";
import { useState } from "react";
import { FormError, FormField } from "#/components/form";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Button } from "#/components/ui/button";
import { FieldGroup } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemDescription,
	ItemTitle,
} from "#/components/ui/item";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { Textarea } from "#/components/ui/textarea";
import { createSchema, m2mAPIs, typeName } from "#/lib/apps";
import { type Application, api } from "#/lib/console-api";
import {
	lines,
	newSecrets,
	type Platform,
	platformKeys,
	platforms,
} from "#/lib/onboarding";
import { applicationsQuery } from "#/lib/queries";
import { FormSheet } from "#/routes/console/-components/form-sheet";
import { apisQuery } from "#/routes/console/apis/index";

// Grouped by type, since the type is the part that can't change later.
const types = [...new Set(platformKeys.map((k) => platforms[k].type))];

// CreateAppSheet asks where users sign in, then only the name and, for
// the web, the callback address. Everything else waits for the
// Application's page.
export function CreateAppSheet({
	open,
	onOpenChange,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
}) {
	const [platform, setPlatform] = useState<Platform>();
	const p = platform && platforms[platform];
	return (
		<FormSheet
			open={open}
			onOpenChange={(o) => {
				onOpenChange(o);
				if (!o) setPlatform(undefined);
			}}
			title="创建应用"
			description={
				p
					? // The platform isn't stored: say which type the app will show as.
						`${p.name}属于「${typeName[p.type]}」，创建后按此类型显示，不能更改。`
					: "选择最接近的平台，将按平台预设配置。"
			}
		>
			{p ? (
				<div className="space-y-6">
					<Item variant="muted">
						<ItemContent>
							<ItemTitle>{p.name}</ItemTitle>
							<ItemDescription>{p.desc}</ItemDescription>
						</ItemContent>
						<ItemActions>
							<Button
								variant="ghost"
								size="sm"
								onClick={() => setPlatform(undefined)}
							>
								更换
							</Button>
						</ItemActions>
					</Item>
					<CreateForm platform={platform} />
				</div>
			) : (
				<div className="space-y-5">
					{types.map((t) => (
						<section key={t} className="space-y-1.5">
							<h3 className="text-muted-foreground text-xs">{typeName[t]}</h3>
							{platformKeys
								.filter((k) => platforms[k].type === t)
								.map((k) => (
									<Item
										key={k}
										variant="outline"
										className="hover:bg-muted"
										render={
											<button type="button" onClick={() => setPlatform(k)} />
										}
									>
										<ItemContent>
											<ItemTitle>{platforms[k].name}</ItemTitle>
											<ItemDescription>{platforms[k].desc}</ItemDescription>
										</ItemContent>
										<ChevronRightIcon className="size-4 text-muted-foreground" />
									</Item>
								))}
						</section>
					))}
				</div>
			)}
		</FormSheet>
	);
}

function CreateForm({ platform }: { platform: Platform }) {
	const p = platforms[platform];
	const needsAPI = p.type === "m2m";
	const registered = m2mAPIs(useSuspenseQuery(apisQuery).data.apis);
	const client = useQueryClient();
	const navigate = useNavigate();
	const save = useMutation({
		mutationFn: (v: {
			name: string;
			redirectUris: string;
			defaultApi?: string;
		}) =>
			api<{ application: Application; secret?: string }>("/applications", {
				method: "POST",
				body: {
					type: p.type,
					settings: {
						name: v.name.trim(),
						redirectUris: lines(v.redirectUris),
						postLogoutRedirectUris: [],
						defaultApi: v.defaultApi,
						refreshTokens: true,
						appleAppIds: [],
						androidApps: [],
					},
				},
			}),
		onSuccess: async ({ application, secret }) => {
			if (secret) {
				newSecrets.set(application.clientId, secret);
			}
			await client.invalidateQueries(applicationsQuery);
			navigate({
				to: "/console/apps/$clientId",
				params: { clientId: application.clientId },
				search: { onboarding: platform },
			});
		},
	});
	const form = useForm({
		defaultValues: { name: "", redirectUris: "", defaultApi: "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: createSchema(!!p.redirect, needsAPI) },
		onSubmit: ({ value }) => save.mutate(value),
	});
	return (
		<form
			noValidate
			className="space-y-6"
			onSubmit={(e) => {
				e.preventDefault();
				form.handleSubmit();
			}}
		>
			<FieldGroup className="gap-6">
				<form.Field name="name">
					{(field) => (
						<FormField field={field} label="名称">
							{(control) => <Input {...control} placeholder="如：星选商城" />}
						</FormField>
					)}
				</form.Field>
				{p.redirect && (
					<form.Field name="redirectUris">
						{(field) => (
							<FormField
								field={field}
								label="回调地址"
								en="redirect URI"
								help="登录完成后跳转回应用的地址，仅允许此处登记的地址。"
							>
								{(control) => (
									<Textarea
										{...control}
										className="font-mono"
										placeholder={`每行一个，如 https://shop.example.com/${platform === "spa" ? "callback" : "auth/callback"}`}
									/>
								)}
							</FormField>
						)}
					</form.Field>
				)}
				{needsAPI && registered.length === 0 && (
					<Alert variant="warning">
						<AlertDescription>
							还没有 API 资源，后端服务需要选择一个默认 API 资源。
							<Link to="/console/apis">添加 API 资源</Link>
						</AlertDescription>
					</Alert>
				)}
				{needsAPI && registered.length > 0 && (
					<form.Field name="defaultApi">
						{(field) => (
							<FormField
								field={field}
								label="默认 API 资源"
								help="access token 仅对该 API 有效，创建后不能更改。调用其他 API 需另建后端服务。"
							>
								{({ id }) => (
									<Select
										value={field.state.value}
										onValueChange={(v) => field.handleChange(v ?? "")}
									>
										<SelectTrigger id={id} className="w-full">
											<SelectValue>
												{(v: string) =>
													registered.find((a) => a.identifier === v)?.name ??
													"请选择"
												}
											</SelectValue>
										</SelectTrigger>
										<SelectContent>
											{registered.map((a) => (
												<SelectItem key={a.identifier} value={a.identifier}>
													{a.name}
													<span className="font-mono text-muted-foreground text-xs">
														{a.identifier}
													</span>
												</SelectItem>
											))}
										</SelectContent>
									</Select>
								)}
							</FormField>
						)}
					</form.Field>
				)}
			</FieldGroup>
			<FormError error={save.error} />
			<Button type="submit" disabled={save.isPending}>
				创建应用
			</Button>
		</form>
	);
}
