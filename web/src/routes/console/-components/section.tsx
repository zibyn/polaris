// Page layout only. If shadcn has the component, use components/ui (ADR 0009).

import { Copy } from "lucide-react";
import type { ReactNode } from "react";
import { copyText } from "#/components/copy-button";
import { FormError } from "#/components/form";
import { Button } from "#/components/ui/button";
import {
	Card,
	CardAction,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
} from "#/components/ui/card";
import { FieldSet } from "#/components/ui/field";
import {
	Tooltip,
	TooltipContent,
	TooltipTrigger,
} from "#/components/ui/tooltip";

// Section is a shadcn Card: the header with the title and any
// section-wide actions, the content, and with a form the save bar in the
// card footer. With a TanStack form the content is that
// form: children are what an editor may change, extra stays usable for
// readers (copying client_id). Without one the rows act on their own. Put
// sections in a space-y-4 parent for the 16px between.
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
		<Card id={id} className="scroll-mt-20">
			<CardHeader className="border-b">
				<CardTitle>{title}</CardTitle>
				{intro && <CardDescription>{intro}</CardDescription>}
				{actions && (
					<CardAction className="flex items-center gap-2">{actions}</CardAction>
				)}
			</CardHeader>
			{form ? (
				<form
					noValidate
					className="flex flex-col gap-(--card-spacing)"
					onSubmit={(e) => {
						e.preventDefault();
						form.handleSubmit();
					}}
				>
					<CardContent className="space-y-6">
						<FieldSet disabled={!editable} className="gap-6">
							{children}
						</FieldSet>
						{extra}
					</CardContent>
					{footer && (
						<CardFooter className="flex-wrap justify-end gap-3">
							{footer}
						</CardFooter>
					)}
				</form>
			) : (
				<CardContent>{children}</CardContent>
			)}
		</Card>
	);
}

// SectionHeading is a section's title and the line under it, with any
// section-wide actions on the right.
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
				<h2 className="font-medium text-base leading-snug">{title}</h2>
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
			<div className="mr-auto">
				<FormError error={save.error} />
			</div>
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
		<Card className="ring-destructive/40">
			<CardHeader>
				<CardTitle className="text-destructive">{title}</CardTitle>
			</CardHeader>
			<CardContent className="space-y-3">{children}</CardContent>
		</Card>
	);
}

// IdLine is one identifier in a detail page's header (Header.ids): a
// grey chip with its name, the value in mono, and a click to copy it. The tooltip carries
// the whole value when it is truncated (a long callback URL).
export function IdLine({ label, value }: { label: string; value: string }) {
	return (
		<Tooltip>
			<TooltipTrigger
				render={
					<Button
						variant="outline"
						size="sm"
						onClick={() => copyText(value)}
						className="min-w-0 max-w-full font-normal"
					/>
				}
			>
				<span className="shrink-0 whitespace-nowrap text-muted-foreground">
					{label}
				</span>
				<span className="truncate font-mono text-xs">{value}</span>
				<Copy
					data-icon="inline-end"
					className="text-muted-foreground"
					aria-hidden
				/>
				<span className="sr-only">复制</span>
			</TooltipTrigger>
			<TooltipContent className="max-w-md break-all">
				{value}（点击复制）
			</TooltipContent>
		</Tooltip>
	);
}
