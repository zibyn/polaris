// Console queries shared across pages: each one's key, fetch, and how a
// write keeps the cache right. Pages call these instead of spelling keys.
import {
	type QueryClient,
	queryOptions,
	useMutation,
	useQueryClient,
} from "@tanstack/react-query";
import { saved } from "#/components/form";
import { replaceApplication, settingsOf } from "#/lib/apps";
import {
	type Application,
	type ApplicationSettings,
	api,
	type ChannelPlugin,
	type ChannelSettings,
	type Policy,
} from "#/lib/console-api";

type Applications = { applications: Application[] };

export const applicationsQuery = queryOptions({
	queryKey: ["applications"],
	queryFn: () => api<Applications>("/applications"),
});

// useSaveApplication writes a few settings and sends the rest back as they
// were, read from the cache. What it sent goes into the cache at once, so
// a save right after another doesn't undo it.
export function useSaveApplication(app: Application) {
	const client = useQueryClient();
	return useMutation({
		mutationFn: async (patch: Partial<ApplicationSettings>) => {
			const latest =
				client
					.getQueryData<Applications>(applicationsQuery.queryKey)
					?.applications.find((a) => a.clientId === app.clientId) ?? app;
			await api(`/applications/${app.clientId}`, {
				method: "PUT",
				body: { ...settingsOf(latest), ...patch },
			});
			return patch;
		},
		onSuccess: (patch) => {
			patchApplication(client, app.clientId, () => patch);
			return client.invalidateQueries(applicationsQuery);
		},
	});
}

// patchApplication writes into the cache what the server now holds, e.g. a
// Logo just uploaded, so the next save sends it back.
export const patchApplication = (
	client: QueryClient,
	clientId: string,
	patch: (a: Application) => Partial<Application>,
) =>
	client.setQueryData<Applications>(applicationsQuery.queryKey, (d) =>
		replaceApplication(d, clientId, (a) => ({ ...a, ...patch(a) })),
	);

const settingsKey = ["settings"];

export const policyQuery = queryOptions({
	queryKey: settingsKey,
	queryFn: () => api<Policy>("/settings"),
});

// useSavePolicy saves one section: PUT /settings takes the whole Policy, so
// the rest goes back as it was, read from the cache. A save writes what it
// sent into the cache at once, so another section's save before the refetch
// doesn't undo it. It toasts 已保存 itself.
export function useSavePolicy() {
	const client = useQueryClient();
	return useMutation({
		mutationFn: async (patch: Partial<Policy>) => {
			const body = { ...client.getQueryData<Policy>(settingsKey), ...patch };
			await api("/settings", { method: "PUT", body });
			return body;
		},
		onSuccess: (body) => {
			client.setQueryData(settingsKey, body);
			saved();
			return client.invalidateQueries({ queryKey: settingsKey });
		},
	});
}

export const channelsQuery = queryOptions({
	queryKey: ["channels"],
	queryFn: () =>
		api<{ plugins: ChannelPlugin[]; channels: ChannelSettings[] }>("/channels"),
});

// invalidateUser refetches what a change to one User shows up in: their
// page, the Users list, Role counts, the overview and the audit log.
export const invalidateUser = (client: QueryClient, sub: string) =>
	Promise.all(
		[
			["user", sub],
			["sessions", sub],
			["passkeys", sub],
			["external-identities", sub],
			["users"],
			["roles"],
			["apis"],
			["overview"],
			["audit"],
		].map((queryKey) => client.invalidateQueries({ queryKey })),
	);
