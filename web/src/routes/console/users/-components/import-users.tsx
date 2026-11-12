import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { Button } from "#/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "#/components/ui/field";
import { Input } from "#/components/ui/input";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "#/components/ui/table";
import { api } from "#/lib/console-api";
import { type ImportRow, readImport, toCSV } from "#/lib/import";
import { FormSheet } from "#/routes/console/-components/form-sheet";

type Failure = { row: ImportRow; message: string };

// ImportUsersSheet reads a CSV, shows what it found, then makes the Users
// one POST /users at a time (ADR 0033), counting as it goes. Closing the
// drawer stops it; the Users made so far stay.
export function ImportUsersSheet({
	open,
	onOpenChange,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
}) {
	const client = useQueryClient();
	const [file, setFile] = useState<ReturnType<typeof readImport>>();
	const [done, setDone] = useState(0);
	const [failures, setFailures] = useState<Failure[]>([]);
	const [state, setState] = useState<"idle" | "running" | "finished">("idle");
	const stop = useRef(false);

	useEffect(() => {
		if (!open) {
			stop.current = true;
			setFile(undefined);
			setDone(0);
			setFailures([]);
			setState("idle");
		}
	}, [open]);

	const rows = file && "rows" in file ? file.rows : [];
	const run = async () => {
		stop.current = false;
		setState("running");
		for (const row of rows) {
			if (stop.current) return;
			try {
				await api("/users", {
					method: "POST",
					body: {
						identifier: row.identifier,
						...(row.passwordHash && { password_hash: row.passwordHash }),
					},
				});
			} catch (e) {
				setFailures((f) => [
					...f,
					{ row, message: e instanceof Error ? e.message : String(e) },
				]);
			}
			setDone((d) => d + 1);
		}
		setState("finished");
		client.invalidateQueries({ queryKey: ["users"] });
	};

	const download = () => {
		const csv = toCSV([
			["identifier", "password_hash", "error"],
			...failures.map((f) => [f.row.identifier, f.row.passwordHash, f.message]),
		]);
		const a = document.createElement("a");
		a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
		a.download = "导入失败的用户.csv";
		a.click();
		URL.revokeObjectURL(a.href);
	};

	return (
		<FormSheet
			open={open}
			onOpenChange={onOpenChange}
			title="导入用户"
			description="每行建一个用户；带原密码哈希的可继续用原密码登录，否则用验证码登录。"
		>
			<div className="flex flex-col gap-5">
				<Field>
					<FieldLabel htmlFor="import-file">CSV 文件</FieldLabel>
					<Input
						id="import-file"
						type="file"
						accept=".csv,text/csv"
						disabled={state === "running"}
						onChange={async (e) => {
							const f = e.target.files?.[0];
							setFile(f ? readImport(await f.text()) : undefined);
							setDone(0);
							setFailures([]);
							setState("idle");
						}}
					/>
					<FieldDescription>
						表头为 <code className="font-mono">identifier</code>
						（手机号、邮箱或用户名）和可选的{" "}
						<code className="font-mono">password_hash</code>
						（argon2id 或 bcrypt）。只有用户名的行必须带哈希。
					</FieldDescription>
				</Field>
				{file && "error" in file && (
					<Alert variant="destructive">
						<AlertDescription>{file.error}</AlertDescription>
					</Alert>
				)}
				{file && "rows" in file && (
					<>
						<p className="text-sm">
							共 {rows.length} 个用户待导入
							{file.problems.length > 0 &&
								`，${file.problems.length} 行有问题将跳过`}
							。
						</p>
						{file.problems.length > 0 && (
							<ul className="list-disc space-y-0.5 pl-5 text-muted-foreground text-sm">
								{file.problems.slice(0, 10).map((p) => (
									<li key={p.line}>
										第 {p.line} 行：{p.message}
									</li>
								))}
							</ul>
						)}
						{rows.length > 0 && (
							<div className="overflow-hidden rounded-lg border">
								<Table>
									<TableHeader>
										<TableRow>
											<TableHead className="w-14">行</TableHead>
											<TableHead>登录标识</TableHead>
											<TableHead>原密码</TableHead>
										</TableRow>
									</TableHeader>
									<TableBody>
										{rows.slice(0, 20).map((r) => (
											<TableRow key={r.line}>
												<TableCell className="text-muted-foreground tabular-nums">
													{r.line}
												</TableCell>
												<TableCell>{r.identifier}</TableCell>
												<TableCell className="text-muted-foreground">
													{r.passwordHash ? "有" : "—"}
												</TableCell>
											</TableRow>
										))}
									</TableBody>
								</Table>
							</div>
						)}
						{state !== "idle" && (
							<div className="space-y-1.5">
								<div className="h-1.5 overflow-hidden rounded-full bg-muted">
									<div
										className="h-full bg-primary transition-[width]"
										style={{ width: `${(100 * done) / (rows.length || 1)}%` }}
									/>
								</div>
								<p className="text-muted-foreground text-sm tabular-nums">
									{state === "running" ? "正在导入" : "导入完成"}：{done} /{" "}
									{rows.length}，成功 {done - failures.length}，失败{" "}
									{failures.length}
								</p>
							</div>
						)}
						{failures.length > 0 && state === "finished" && (
							<div className="space-y-2">
								<ul className="list-disc space-y-0.5 pl-5 text-sm">
									{failures.slice(0, 10).map((f) => (
										<li key={f.row.line}>
											第 {f.row.line} 行 {f.row.identifier}：{f.message}
										</li>
									))}
								</ul>
								<Button variant="outline" size="sm" onClick={download}>
									下载失败的行
								</Button>
							</div>
						)}
						{state === "idle" && rows.length > 0 && (
							<Button className="self-start" onClick={run}>
								导入 {rows.length} 个用户
							</Button>
						)}
					</>
				)}
			</div>
		</FormSheet>
	);
}
