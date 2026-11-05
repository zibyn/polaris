// 用户资料 beyond the nickname and avatar: the other OIDC standard profile
// claims and the address (ADR 0029), shown and edited the same way in the
// account center and the console. The server checks every field; its
// refusal shows in the form.

import { useForm } from "@tanstack/react-form";
import { useMutation } from "@tanstack/react-query";
import { FormError, FormField } from "#/components/form";
import { Button } from "#/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogTitle,
} from "#/components/ui/dialog";
import { Input } from "#/components/ui/input";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "#/components/ui/select";
import { Textarea } from "#/components/ui/textarea";

export type Address = {
	formatted?: string;
	street_address?: string;
	locality?: string;
	region?: string;
	postal_code?: string;
	country?: string;
};
// ProfileClaims is named as the claims are, as the server sends them.
export type ProfileClaims = {
	name?: string;
	given_name?: string;
	family_name?: string;
	middle_name?: string;
	profile?: string;
	website?: string;
	gender?: string;
	birthdate?: string;
	zoneinfo?: string;
	locale?: string;
	address?: Address;
	updated_at?: number;
};

type TextKey = Exclude<keyof ProfileClaims, "address" | "updated_at">;
type AddressKey = keyof Address;

const fields: { key: TextKey; label: string; placeholder?: string }[] = [
	{ key: "name", label: "姓名", placeholder: "展示用的全名" },
	{ key: "family_name", label: "姓" },
	{ key: "given_name", label: "名" },
	{ key: "middle_name", label: "中间名" },
	{ key: "gender", label: "性别" },
	{
		key: "birthdate",
		label: "生日",
		placeholder: "1990-01-31、0000-01-31 或 1990",
	},
	{ key: "website", label: "网站", placeholder: "https://" },
	{ key: "profile", label: "个人主页", placeholder: "https://" },
	{ key: "zoneinfo", label: "时区", placeholder: "如 Asia/Shanghai" },
	{ key: "locale", label: "语言", placeholder: "如 zh-CN" },
];
const addressFields: { key: AddressKey; label: string }[] = [
	{ key: "country", label: "国家/地区" },
	{ key: "region", label: "省/州" },
	{ key: "locality", label: "城市" },
	{ key: "street_address", label: "街道地址" },
	{ key: "postal_code", label: "邮编" },
	{ key: "formatted", label: "完整地址" },
];
const genderName: Record<string, string> = {
	"": "未设置",
	female: "女",
	male: "男",
	other: "其他",
};

export const addressText = (a?: Address) =>
	a?.formatted ||
	[a?.country, a?.region, a?.locality, a?.street_address, a?.postal_code]
		.filter(Boolean)
		.join(" ");

// ProfileDetails lists the fields that are set, or says none is.
export function ProfileDetails({ p }: { p: ProfileClaims }) {
	const rows: [string, string][] = fields
		.filter((f) => p[f.key])
		.map((f) => {
			const v = p[f.key] as string;
			return [f.label, f.key === "gender" ? (genderName[v] ?? v) : v];
		});
	const address = addressText(p.address);
	if (address) rows.push(["地址", address]);
	if (rows.length === 0) {
		return <span className="text-muted-foreground">未设置</span>;
	}
	return (
		<dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
			{rows.map(([label, value]) => (
				<div key={label} className="contents">
					<dt className="text-muted-foreground">{label}</dt>
					<dd className="min-w-0 whitespace-pre-line break-words">{value}</dd>
				</div>
			))}
		</dl>
	);
}

// EditProfileDetails edits every field ProfileDetails shows; save sends
// them all, an empty one clearing it.
export function EditProfileDetails({
	p,
	save,
	onSaved,
	onClose,
}: {
	p: ProfileClaims;
	save: (patch: ProfileClaims) => Promise<unknown>;
	onSaved: () => Promise<void> | void;
	onClose: () => void;
}) {
	const mutation = useMutation({
		mutationFn: save,
		onSuccess: async () => {
			await onSaved();
			onClose();
		},
	});
	const form = useForm({
		defaultValues: {
			...Object.fromEntries(fields.map((f) => [f.key, p[f.key] ?? ""])),
			...Object.fromEntries(
				addressFields.map((f) => [`addr_${f.key}`, p.address?.[f.key] ?? ""]),
			),
		} as Record<string, string>,
		onSubmit: ({ value }) => {
			const patch: ProfileClaims = Object.fromEntries(
				fields.map((f) => [f.key, value[f.key].trim()]),
			);
			patch.address = Object.fromEntries(
				addressFields.map((f) => [f.key, value[`addr_${f.key}`].trim()]),
			);
			mutation.mutate(patch);
		},
	});
	const genders = Object.keys(genderName);
	if (p.gender && !genders.includes(p.gender)) genders.push(p.gender);
	return (
		<Dialog open onOpenChange={(open) => !open && onClose()}>
			<DialogContent className="max-h-[90dvh] overflow-y-auto">
				<DialogTitle>修改详细资料</DialogTitle>
				<DialogDescription>
					应用经 profile、address 授权读取这些信息。留空即清除。
				</DialogDescription>
				<form
					noValidate
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					{fields.map((f) => (
						<form.Field key={f.key} name={f.key}>
							{(field) => (
								<FormField field={field} label={f.label}>
									{(control) =>
										f.key === "gender" ? (
											<Select
												value={field.state.value}
												onValueChange={(v) => field.handleChange(v as string)}
											>
												<SelectTrigger
													id={control.id}
													aria-invalid={control["aria-invalid"]}
													className="w-full"
												>
													<SelectValue>
														{(v: string) => genderName[v] ?? v}
													</SelectValue>
												</SelectTrigger>
												<SelectContent>
													{genders.map((g) => (
														<SelectItem key={g} value={g}>
															{genderName[g] ?? g}
														</SelectItem>
													))}
												</SelectContent>
											</Select>
										) : (
											<Input
												{...control}
												autoComplete="off"
												placeholder={f.placeholder}
											/>
										)
									}
								</FormField>
							)}
						</form.Field>
					))}
					<p className="pt-2 font-medium text-sm">地址</p>
					{addressFields.map((f) => (
						<form.Field key={f.key} name={`addr_${f.key}`}>
							{(field) => (
								<FormField field={field} label={f.label}>
									{(control) =>
										f.key === "formatted" || f.key === "street_address" ? (
											<Textarea {...control} autoComplete="off" rows={2} />
										) : (
											<Input {...control} autoComplete="off" />
										)
									}
								</FormField>
							)}
						</form.Field>
					))}
					<FormError error={mutation.error} />
					<div className="flex justify-end gap-2">
						<Button type="button" variant="outline" onClick={onClose}>
							取消
						</Button>
						<Button type="submit" disabled={mutation.isPending}>
							保存
						</Button>
					</div>
				</form>
			</DialogContent>
		</Dialog>
	);
}
