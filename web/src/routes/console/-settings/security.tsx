import {
	queryOptions,
	useMutation,
	useQueryClient,
	useSuspenseQuery,
} from "@tanstack/react-query";
import { failed } from "#/components/form";
import { ItemList, PropRow } from "#/components/item-list";
import { Button } from "#/components/ui/button";
import { api, type SigningKey } from "#/lib/console-api";
import {
	asksShorterRetention,
	lastRotation,
	rotatedRecently,
} from "#/lib/login";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { Section } from "#/routes/console/-components/section";
import { useCan } from "#/routes/console/route";
import { PolicyNumber } from "./policy";

const date = (s: string) => new Date(s).toLocaleString("zh-CN");

export const signingKeysQuery = queryOptions({
	queryKey: ["signing-keys"],
	queryFn: () => api<{ keys: SigningKey[] }>("/signing-keys"),
});

export function SecurityTab() {
	return (
		<div className="space-y-10">
			<SigningKeys />
			<PolicyNumber
				title="审计保留期"
				field="auditRetentionDays"
				label="保留期限"
				suffix="天"
				help="超过该天数的审计记录会自动删除。"
				min={1}
				confirm={{
					when: asksShorterRetention,
					title: "缩短审计保留期？",
					action: "缩短保留期",
					body: "超出新期限的记录将在一小时内删除，此操作无法撤销。",
				}}
			/>
		</div>
	);
}

function SigningKeys() {
	const can = useCan();
	const client = useQueryClient();
	const list = useSuspenseQuery(signingKeysQuery).data.keys;
	const rotate = useMutation({
		mutationFn: () => api("/signing-keys/rotate", { method: "POST" }),
		onSuccess: () => client.invalidateQueries(signingKeysQuery),
		onError: failed("轮换签名密钥失败"),
	});
	const current = list.find((k) => k.current);
	const rotated = lastRotation(list);
	const recent = !!rotated && rotatedRecently(rotated);
	return (
		<Section
			title="令牌签名密钥"
			intro="当前密钥用于签发令牌。轮换后，上一个密钥仅用于验证已签发的令牌。"
			actions={
				can("keys:rotate") && (
					<ConfirmDialog
						trigger={
							<Button variant="outline" disabled={rotate.isPending}>
								轮换签名密钥
							</Button>
						}
						title="轮换令牌签名密钥？"
						action="轮换签名密钥"
						onConfirm={() => rotate.mutate()}
					>
						<p>
							{rotated ? `上次轮换于 ${date(rotated)}。` : "尚未轮换。"}
							新密钥将用于签发令牌，上一个密钥仍可验证已签发的令牌。更早的密钥会被删除，由它签发且未过期的令牌立即失效。
						</p>
						{recent && (
							<p className="mt-2 font-medium text-destructive">
								距上次轮换不到 1
								天。再次轮换会使上一个密钥签发的令牌立即失效，刚登录的用户可能需要重新登录。
							</p>
						)}
					</ConfirmDialog>
				)
			}
		>
			{current && (
				<p className="mb-2 text-[13px] text-muted-foreground">
					{rotated
						? `上次轮换于 ${date(rotated)}`
						: `尚未轮换，当前密钥创建于 ${date(current.createdAt)}`}
				</p>
			)}
			<ItemList>
				{list.map((k) => (
					<PropRow
						key={k.kid}
						label={k.current ? "当前" : "上一个"}
						hint={`创建于 ${date(k.createdAt)}`}
					>
						<span className="break-all font-mono text-sm">{k.kid}</span>
					</PropRow>
				))}
			</ItemList>
		</Section>
	);
}
