import { revalidateLogic, useForm } from "@tanstack/react-form";
import { useMutation } from "@tanstack/react-query";
import { useRef } from "react";
import { toast } from "sonner";
import { FormField, failed, saved } from "#/components/form";
import { Star } from "#/components/star";
import { Button } from "#/components/ui/button";
import { Input } from "#/components/ui/input";
import { brandSchema, logoProblem } from "#/lib/brand";
import { api, type Brand } from "#/lib/console-api";
import { SaveBar, Section } from "./section";

// BrandSection edits a 品牌 (ADR 0028): the instance's, or an Application's
// items over it. The Logo uploads and goes on its own, at once; the name
// and colour save with the section, the Logo sent back as it stands.
export function BrandSection({
	intro,
	brand,
	editable,
	follows,
	followsColor = follows,
	logoPath,
	onLogo,
	save,
}: {
	intro: string;
	brand?: Brand;
	editable: boolean;
	follows: string; // what an empty item shows instead
	followsColor?: string; // what an empty 主色 shows, when not follows
	logoPath: string; // the Management API path its Logo uploads to
	onLogo: (logo: string | undefined) => Promise<unknown>; // after an upload or removal
	save: {
		mutate: (b: Brand, o: { onSuccess: () => void }) => void;
		isPending: boolean;
		error: Error | null;
	};
}) {
	const file = useRef<HTMLInputElement>(null);
	const upload = useMutation({
		mutationFn: (f: File) =>
			api<{ logo: string }>(logoPath, { method: "PUT", body: f }),
		onSuccess: async (r) => {
			await onLogo(r.logo);
			saved();
		},
		onError: failed("上传 Logo 失败"),
	});
	const remove = useMutation({
		mutationFn: () => api(logoPath, { method: "DELETE" }),
		onSuccess: async () => {
			await onLogo(undefined);
			saved();
		},
		onError: failed("移除 Logo 失败"),
	});
	const form = useForm({
		defaultValues: { name: brand?.name ?? "", color: brand?.color ?? "" },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: brandSchema },
		onSubmit: ({ value }) =>
			save.mutate(
				{
					name: value.name.trim(),
					color: value.color.trim().toLowerCase(),
					logo: brand?.logo,
				},
				{ onSuccess: saved },
			),
	});
	return (
		<Section
			title="品牌"
			intro={intro}
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<div className="space-y-2">
				<p className="font-medium text-[13px]">Logo</p>
				<div className="flex items-center gap-3">
					{brand?.logo ? (
						<img
							src={`/brand-logos/${brand.logo}`}
							alt="当前 Logo"
							className="h-10 max-w-40 rounded-md border object-contain p-1"
						/>
					) : (
						<>
							<span className="grid size-10 place-items-center rounded-md border bg-canvas text-primary">
								<Star className="size-4" />
							</span>
							<span className="text-muted-foreground text-sm">{follows}</span>
						</>
					)}
					{editable && (
						<>
							<input
								ref={file}
								type="file"
								accept="image/png,image/webp,image/svg+xml"
								className="hidden"
								onChange={(e) => {
									const f = e.target.files?.[0];
									e.target.value = "";
									if (!f) return;
									const problem = logoProblem(f);
									if (problem) toast.error(problem);
									else upload.mutate(f);
								}}
							/>
							<Button
								type="button"
								variant="outline"
								size="sm"
								disabled={upload.isPending}
								onClick={() => file.current?.click()}
							>
								{brand?.logo ? "更换" : "上传"}
							</Button>
							{brand?.logo && (
								<Button
									type="button"
									variant="ghost"
									size="sm"
									disabled={remove.isPending}
									onClick={() => remove.mutate()}
								>
									移除
								</Button>
							)}
						</>
					)}
				</div>
				<p className="text-[13px] text-muted-foreground">
					PNG、WebP 或 SVG，不超过 1
					MB。替换登录页星标，并用作浏览器标签页图标。
				</p>
			</div>
			<form.Field name="name">
				{(field) => (
					<FormField
						field={field}
						label="品牌名"
						help="显示在登录页品牌区和浏览器标签页标题中。"
					>
						{(control) => (
							<Input {...control} className="w-64" placeholder={follows} />
						)}
					</FormField>
				)}
			</form.Field>
			<form.Field name="color">
				{(field) => (
					<FormField
						field={field}
						label="主色"
						help="用于按钮和链接，需与白色文字的对比度不低于 4.5:1。"
					>
						{(control) => (
							<div className="flex items-center gap-2">
								<input
									type="color"
									aria-label="选择主色"
									disabled={!editable}
									value={
										/^#[0-9a-fA-F]{6}$/.test(field.state.value)
											? field.state.value
											: "#7048e8"
									}
									onChange={(e) => field.handleChange(e.target.value)}
									className="h-9 w-12 cursor-pointer rounded-md border bg-transparent"
								/>
								<Input
									{...control}
									className="w-32 font-mono"
									placeholder={followsColor}
								/>
							</div>
						)}
					</FormField>
				)}
			</form.Field>
		</Section>
	);
}
