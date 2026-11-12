import { useQuery } from "@tanstack/react-query";
import {
	createFileRoute,
	Link,
	notFound,
	useParams,
} from "@tanstack/react-router";
import type { ReactNode } from "react";
import { applicationsQuery } from "#/lib/queries";
import { apisQuery } from "#/routes/console/apis/index";

// The API resource and what sits under it (its Roles' pages) share the
// crumb and the check that it exists.
export const Route = createFileRoute("/console/apis/$api")({
	staticData: { crumb: APIName },
	loader: async ({ context: { queryClient }, params }) => {
		const [apis] = await Promise.all([
			queryClient.ensureQueryData(apisQuery),
			queryClient.ensureQueryData(applicationsQuery),
		]);
		if (!apis.apis.some((a) => a.identifier === params.api)) {
			throw notFound();
		}
	},
	notFoundComponent: () => (
		<p className="text-sm">
			API 资源不存在或已被删除。
			<Link to="/console/apis" className="underline">
				返回 API 资源列表
			</Link>
		</p>
	),
});

// APIName is the API resource's crumb, kept current by the query.
function APIName(): ReactNode {
	const { api: identifier } = useParams({ from: "/console/apis/$api" });
	return useQuery(apisQuery).data?.apis.find((a) => a.identifier === identifier)
		?.name;
}
