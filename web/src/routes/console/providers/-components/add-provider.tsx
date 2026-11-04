import { useSuspenseQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ChevronRightIcon } from "lucide-react";
import { useState } from "react";
import { Button } from "#/components/ui/button";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemTitle,
} from "#/components/ui/item";
import { FormSheet } from "#/routes/console/-components/form-sheet";
import { providersQuery } from "#/routes/console/providers/index";
import { ProviderForm } from "./provider-form";

// Generic protocols, for self-hosted identity services like Keycloak.
const GENERIC = ["oidc", "oauth2"];

// AddProviderSheet is the type catalog (the types ship with the binary,
// ADR 0004), then the form for the one picked, in a drawer over the list.
export function AddProviderSheet({
	open,
	onOpenChange,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
}) {
	const { types } = useSuspenseQuery(providersQuery).data;
	const navigate = useNavigate();
	const [key, setKey] = useState<string>();
	const type = types.find((t) => t.key === key);
	const generic = (t: { key: string }) => GENERIC.includes(t.key);
	const groups = [
		["平台", types.filter((t) => !generic(t))],
		["自建身份服务", types.filter(generic)],
	] as const;
	return (
		<FormSheet
			open={open}
			onOpenChange={(o) => {
				onOpenChange(o);
				if (!o) setKey(undefined);
			}}
			title="添加认证源"
		>
			{type ? (
				<div className="space-y-6">
					<Item variant="muted">
						<ItemContent>
							<ItemTitle>{type.name}</ItemTitle>
						</ItemContent>
						<ItemActions>
							<Button
								variant="ghost"
								size="sm"
								onClick={() => setKey(undefined)}
							>
								更换
							</Button>
						</ItemActions>
					</Item>
					<ProviderForm
						type={type}
						onCancel={() => onOpenChange(false)}
						onDone={(id) =>
							navigate({ to: "/console/providers/$id", params: { id } })
						}
					/>
				</div>
			) : (
				<div className="space-y-5">
					{groups.map(([title, list]) => (
						<section key={title} className="space-y-1.5">
							<h3 className="text-muted-foreground text-xs">{title}</h3>
							{list.map((t) => (
								<Item
									key={t.key}
									variant="outline"
									size="sm"
									className="hover:bg-muted"
									render={
										<button type="button" onClick={() => setKey(t.key)} />
									}
								>
									<ItemContent>
										<ItemTitle>{t.name}</ItemTitle>
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
