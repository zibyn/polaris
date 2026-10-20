import { useQuery, useSuspenseQuery } from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	useNavigate,
	useSearch,
} from "@tanstack/react-router";
import { z } from "zod";
import { buttonVariants } from "#/components/ui/button";
import {
	Card,
	CardDescription,
	CardHeader,
	CardTitle,
} from "#/components/ui/card";
import { providersQuery } from "#/routes/console/providers/index";
import { type Header, useCan } from "#/routes/console/route";
import { ProviderForm } from "./-components/provider-form";

const search = z.object({
	// a Provider type's key, picked from the catalog below
	type: z.string().optional().catch(undefined),
});

export const Route = createFileRoute("/console/providers/new")({
	staticData: { crumb: "添加认证源", useHeader },
	validateSearch: search,
	loader: ({ context: { queryClient } }) =>
		queryClient.ensureQueryData(providersQuery),
	component: AddProvider,
});

// useHeader titles the type catalog, or the form once a type is picked;
// without the Permission there's no header, only the note.
function useHeader(): Header | null {
	const { type: key } = useSearch({ from: "/console/providers/new" });
	// The header draws around the page's loading, so it reads the cache
	// without suspending.
	const type = useQuery(providersQuery).data?.types.find((t) => t.key === key);
	const can = useCan();
	if (!can("config:write")) {
		return null;
	}
	if (!type) {
		return {
			title: "添加认证源",
			description: "常见供应商开箱可用；自建的选通用 OIDC 或 OAuth2。",
		};
	}
	return {
		title: `添加${type.name}`,
		actions: (
			<Link
				to="/console/providers/new"
				search={{}}
				className={buttonVariants({ variant: "outline" })}
			>
				换个类型
			</Link>
		),
	};
}

// AddProvider is the type catalog (the types ship with the binary,
// ADR 0004), then the form for the one picked.
function AddProvider() {
	const { type: key } = Route.useSearch();
	const { types } = useSuspenseQuery(providersQuery).data;
	const can = useCan();
	const navigate = useNavigate();
	const type = types.find((t) => t.key === key);
	if (!can("config:write")) {
		return <p className="text-sm">需要「管理员」角色才能添加认证源。</p>;
	}
	return type ? (
		<ProviderForm
			type={type}
			onDone={(id) =>
				navigate({ to: "/console/providers/$id", params: { id } })
			}
		/>
	) : (
		<div className="grid gap-4 sm:grid-cols-2">
			{types.map((t) => (
				<Link
					key={t.key}
					from={Route.fullPath}
					search={{ type: t.key }}
					className="block"
				>
					<Card
						size="sm"
						className="h-full transition-colors hover:ring-primary/40"
					>
						<CardHeader>
							<CardTitle>{t.name}</CardTitle>
							<CardDescription>
								要填：{t.fields.map((f) => f.label).join("、")}
							</CardDescription>
						</CardHeader>
					</Card>
				</Link>
			))}
		</div>
	);
}
