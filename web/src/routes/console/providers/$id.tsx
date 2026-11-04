import { useQuery, useSuspenseQuery } from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	notFound,
	useParams,
} from "@tanstack/react-router";
import type { ReactNode } from "react";
import { Badge } from "#/components/ui/badge";
import { IdLine } from "#/routes/console/-components/section";
import { providersQuery } from "#/routes/console/providers/index";
import { type Header, useCan } from "#/routes/console/route";
import { ProviderForm } from "./-components/provider-form";

export const Route = createFileRoute("/console/providers/$id")({
	staticData: { crumb: ProviderName, useHeader },
	loader: async ({ context: { queryClient }, params }) => {
		const { providers } = await queryClient.ensureQueryData(providersQuery);
		if (!providers.some((p) => p.id === params.id)) {
			throw notFound();
		}
	},
	notFoundComponent: () => (
		<p className="text-sm">
			认证源不存在或已被删除。
			<Link to="/console/providers" className="underline">
				返回认证源列表
			</Link>
		</p>
	),
	component: ProviderPage,
});

const useProvider = (id: string) =>
	useQuery(providersQuery).data?.providers.find((p) => p.id === id);

// ProviderName is the Provider's crumb, kept current by the query.
function ProviderName(): ReactNode {
	const { id } = useParams({ from: "/console/providers/$id" });
	return useProvider(id)?.name;
}

// useHeader heads a Provider's page: its name, type and enabled state, why
// it can't be edited.
function useHeader(): Header | null {
	const { id } = useParams({ from: "/console/providers/$id" });
	const p = useProvider(id);
	const type = useQuery(providersQuery).data?.types.find(
		(t) => t.key === p?.type,
	);
	const can = useCan();
	if (!p) {
		return null;
	}
	const editable = can("config:write");
	return {
		title: p.name,
		badges: (
			<>
				{type && <Badge variant="secondary">{type.name}</Badge>}
				{p.enabled ? (
					<Badge variant="success">已启用</Badge>
				) : (
					<Badge variant="secondary">已停用</Badge>
				)}
			</>
		),
		ids: (
			<>
				<IdLine label="Provider ID" value={p.id} />
				<span title={p.callbackUrl} className="flex min-w-0 max-w-full">
					<IdLine label="回调 URL" value={p.callbackUrl} />
				</span>
			</>
		),
		details: !editable && (
			<p className="text-muted-foreground text-sm">
				需要「管理员」角色才能修改。
			</p>
		),
	};
}

function ProviderPage() {
	const { id } = Route.useParams();
	const { types, providers } = useSuspenseQuery(providersQuery).data;
	const can = useCan();
	// The loader checked; this covers it going in a later refetch.
	const p = providers.find((x) => x.id === id);
	if (!p) {
		throw notFound();
	}
	const type = types.find((t) => t.key === p.type);
	if (!type) {
		return <p className="text-sm">该认证源的类型已不可用，无法编辑配置。</p>;
	}
	// key: a saved secret changes the placeholders, so the form remounts.
	return (
		<ProviderForm
			key={`${p.id}-${JSON.stringify(p.secrets)}`}
			type={type}
			current={p}
			editable={can("config:write")}
		/>
	);
}
