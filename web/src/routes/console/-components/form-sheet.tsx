// Page layout only. If shadcn has the component, use components/ui (ADR 0009).

import type { ReactNode } from "react";
import {
	Sheet,
	SheetContent,
	SheetDescription,
	SheetHeader,
	SheetTitle,
} from "#/components/ui/sheet";

// FormSheet holds a console form in a right-hand drawer, so the list or
// detail page it belongs to stays in view behind it. Its children are the
// form, including its submit button.
export function FormSheet({
	open,
	onOpenChange,
	title,
	description,
	children,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	title: string;
	description?: ReactNode;
	children: ReactNode;
}) {
	return (
		<Sheet open={open} onOpenChange={onOpenChange}>
			<SheetContent
				side="right"
				className="w-full gap-0 overflow-y-auto p-0 sm:max-w-lg"
			>
				<SheetHeader className="border-b px-6 py-5 pr-14">
					<SheetTitle>{title}</SheetTitle>
					{description && <SheetDescription>{description}</SheetDescription>}
				</SheetHeader>
				<div className="px-6 py-5">{children}</div>
			</SheetContent>
		</Sheet>
	);
}
