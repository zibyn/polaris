import { Children, Fragment, isValidElement, type ReactNode } from "react";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemDescription,
	ItemGroup,
	ItemSeparator,
} from "#/components/ui/item";

// PropRow is one labelled row of an ItemList, made of shadcn Item parts:
// the label in a fixed column, the value right beside it (not across the
// panel), actions at the end. On narrow screens the label sits above.
export function PropRow({
	id,
	label,
	hint,
	actions,
	children,
}: {
	id?: string;
	label: ReactNode;
	hint?: ReactNode;
	actions?: ReactNode;
	children?: ReactNode;
}) {
	return (
		<Item id={id} size="sm" className="px-0">
			<ItemContent className="flex-none basis-full sm:basis-36">
				<ItemDescription className="text-[13px]">{label}</ItemDescription>
			</ItemContent>
			{/* A second ItemContent is flex-none in shadcn; the value grows. */}
			<ItemContent className="min-w-0 flex-1!">
				<div>{children}</div>
				{hint && (
					<ItemDescription className="text-[13px]">{hint}</ItemDescription>
				)}
			</ItemContent>
			{actions && <ItemActions>{actions}</ItemActions>}
		</Item>
	);
}

// ItemList is a list of Items on no tint, a rule between each (#76).
// Its Items have no inset, so they line up with the section title.
export function ItemList({ children }: { children: ReactNode }) {
	return (
		<ItemGroup className="gap-0 has-data-[size=sm]:gap-0 has-data-[size=xs]:gap-0 [&>[data-slot=item]]:px-0">
			{Children.toArray(children).map((child, i) => (
				<Fragment key={isValidElement(child) ? child.key : i}>
					{i > 0 && <ItemSeparator className="my-0" />}
					{child}
				</Fragment>
			))}
		</ItemGroup>
	);
}
