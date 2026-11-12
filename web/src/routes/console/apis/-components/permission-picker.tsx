import { useState } from "react";
import { Checkbox } from "#/components/ui/checkbox";
import { Input } from "#/components/ui/input";
import { Label } from "#/components/ui/label";
import { matching, toggled } from "#/lib/apis";
import type { PermissionInfo } from "#/lib/console-api";

// PermissionPicker ticks a Role's Permissions: a search over key and name,
// 全选 over what the search shows, and one row per Permission with its key.
export function PermissionPicker({
	permissions,
	value,
	onChange,
	disabled,
}: {
	permissions: PermissionInfo[];
	value: string[];
	onChange: (keys: string[]) => void;
	disabled?: boolean;
}) {
	const [q, setQ] = useState("");
	const shown = matching(permissions, q);
	const keys = shown.map((p) => p.key);
	const ticked = keys.filter((k) => value.includes(k)).length;
	return (
		<div className="space-y-2">
			<div className="flex flex-wrap items-center gap-x-4 gap-y-2">
				<Input
					type="search"
					value={q}
					onChange={(e) => setQ(e.target.value)}
					placeholder="搜索权限 key 或名称"
					aria-label="搜索权限"
					className="max-w-64"
				/>
				<Label className="font-normal">
					<Checkbox
						disabled={disabled || keys.length === 0}
						checked={keys.length > 0 && ticked === keys.length}
						indeterminate={ticked > 0 && ticked < keys.length}
						onCheckedChange={(on) => onChange(toggled(value, keys, on))}
					/>
					{q.trim() ? "全选搜索结果" : "全选"}
				</Label>
				<span className="ml-auto text-[13px] text-muted-foreground">
					已选 {value.length} / {permissions.length}
				</span>
			</div>
			<div className="max-h-72 divide-y overflow-y-auto rounded-lg border">
				{shown.map((p) => (
					<Label key={p.key} className="flex px-3 py-2 font-normal">
						<Checkbox
							disabled={disabled}
							checked={value.includes(p.key)}
							onCheckedChange={(on) => onChange(toggled(value, [p.key], on))}
						/>
						{p.name}
						<span className="ml-auto font-mono text-muted-foreground text-xs">
							{p.key}
						</span>
					</Label>
				))}
				{shown.length === 0 && (
					<p className="px-3 py-2 text-[13px] text-muted-foreground">
						没有匹配的权限。
					</p>
				)}
			</div>
		</div>
	);
}
