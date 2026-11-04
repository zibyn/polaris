// Page layout only. If shadcn has the component, use components/ui (ADR 0009).

import { Copy } from "lucide-react";
import type { ReactNode } from "react";
import { copyText } from "#/components/copy-button";
import { FormError } from "#/components/form";
import { Button } from "#/components/ui/button";
import { FieldSet } from "#/components/ui/field";
import {
	Tooltip,
	TooltipContent,
	TooltipTrigger,
} from "#/components/ui/tooltip";

// Section is a section title and its content, no card around it. With a
// TanStack form the content is that form: children are what an editor may
// change, extra stays usable for readers (copying client_id). Without one
// the rows act on their own. Put sections in a space-y-10 parent for the
// 40px between.
export function Section({
	title,
	intro,
	id,
	actions,
	editable = true,
	form,
	extra,
	footer,
	children,
}: {
	title: string;
	intro?: ReactNode;
	id?: string; // an anchor target, such as #passkeys from passkey-endpoints
	actions?: ReactNode; // section-wide buttons, right of the title
	editable?: boolean;
	form?: { handleSubmit: () => unknown };
	extra?: ReactNode;
	footer?: ReactNode;
	children: ReactNode;
}) {
	return (
		<section id={id}>
			<SectionHeading title={title} intro={intro} actions={actions} />
			{form ? (
				<form
					noValidate
					className="mt-4 space-y-6"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					<FieldSet disabled={!editable} className="gap-6">
						{children}
					</FieldSet>
					{extra}
					{footer}
				</form>
			) : (
				<div className="mt-4">{children}</div>
			)}
		</section>
	);
}

// SectionHeading is a section's title and the line under it, with any
// section-wide actions on the right. Content follows mt-4 below it.
export function SectionHeading({
	title,
	intro,
	actions,
}: {
	title: string;
	intro?: ReactNode;
	actions?: ReactNode;
}) {
	return (
		<div className="flex flex-wrap items-start gap-x-4 gap-y-2">
			<div className="min-w-0 flex-1">
				<h2 className="font-semibold text-[15px]">{title}</h2>
				{intro && (
					<p className="mt-1 text-[13px] text-muted-foreground">{intro}</p>
				)}
			</div>
			{actions && <div className="flex items-center gap-2">{actions}</div>}
		</div>
	);
}

// SaveBar is a section's save button, under why the server turned the
// last save down. A save that goes through says so in a toast.
export function SaveBar({
	save,
}: {
	save: { isPending: boolean; error: Error | null };
}) {
	return (
		<>
			<FormError error={save.error} />
			<Button type="submit" disabled={save.isPending}>
				保存
			</Button>
		</>
	);
}

// DangerZone is the red-bordered block at the foot of a page: what
// deleting does first, then the button.
export function DangerZone({
	title,
	children,
}: {
	title: string;
	children: ReactNode;
}) {
	return (
		<section className="space-y-3 rounded-xl border border-destructive/50 p-6">
			<h2 className="font-semibold text-[15px] text-destructive">{title}</h2>
			{children}
		</section>
	);
}

// IdLine is one identifier in a detail page's header (Header.ids): its
// name, the value in mono, and a click to copy it. The tooltip carries
// the whole value when it is truncated (a long callback URL).
export function IdLine({ label, value }: { label: string; value: string }) {
	return (
		<span className="inline-flex min-w-0 items-center gap-1 text-[13px]">
			<span className="shrink-0 whitespace-nowrap text-muted-foreground">
				{label}
			</span>
			<Tooltip>
				<TooltipTrigger
					render={
						<Button
							variant="ghost"
							size="xs"
							onClick={() => copyText(value)}
							className="min-w-0 font-mono text-primary-ink"
						/>
					}
				>
					<span className="truncate">{value}</span>
					<Copy data-icon="inline-end" aria-hidden />
					<span className="sr-only">复制</span>
				</TooltipTrigger>
				<TooltipContent className="max-w-md break-all">
					{value}（点击复制）
				</TooltipContent>
			</Tooltip>
		</span>
	);
}
