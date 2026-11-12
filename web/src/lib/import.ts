// 导入用户 from a CSV (docs/spec/consoles.md「用户」): one POST /users per
// row (ADR 0033). Pure TypeScript: tested with node --test.

export type ImportRow = {
	line: number; // 1-based, counting the header, as a spreadsheet shows it
	identifier: string;
	passwordHash: string;
};

// parseCSV splits RFC 4180 text into rows of fields: quoted fields may hold
// commas (argon2id hashes do), newlines and "" for a quote.
export function parseCSV(text: string): string[][] {
	const rows: string[][] = [];
	let row: string[] = [];
	let field = "";
	let quoted = false;
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (quoted) {
			if (c === '"' && text[i + 1] === '"') {
				field += '"';
				i++;
			} else if (c === '"') {
				quoted = false;
			} else {
				field += c;
			}
		} else if (c === '"') {
			quoted = true;
		} else if (c === ",") {
			row.push(field);
			field = "";
		} else if (c === "\n" || c === "\r") {
			if (c === "\r" && text[i + 1] === "\n") i++;
			row.push(field);
			rows.push(row);
			row = [];
			field = "";
		} else {
			field += c;
		}
	}
	if (field || row.length) {
		row.push(field);
		rows.push(row);
	}
	return rows;
}

// readImport takes the CSV's rows: a header naming identifier (required)
// and password_hash (optional), in any order; blank lines are skipped.
export function readImport(
	text: string,
):
	| { error: string }
	| { rows: ImportRow[]; problems: { line: number; message: string }[] } {
	const [header, ...body] = parseCSV(text.replace(/^﻿/, ""));
	const cols = (header ?? []).map((h) => h.trim().toLowerCase());
	const id = cols.indexOf("identifier");
	const hash = cols.indexOf("password_hash");
	if (id < 0) {
		return { error: "第一行需要是表头，至少包含 identifier 列。" };
	}
	const rows: ImportRow[] = [];
	const problems: { line: number; message: string }[] = [];
	const seen = new Map<string, number>();
	body.forEach((f, i) => {
		const line = i + 2;
		if (f.every((v) => !v.trim())) return;
		const identifier = (f[id] ?? "").trim();
		if (!identifier) {
			problems.push({ line, message: "缺少 identifier" });
			return;
		}
		const first = seen.get(identifier.toLowerCase());
		if (first) {
			problems.push({ line, message: `与第 ${first} 行重复` });
			return;
		}
		seen.set(identifier.toLowerCase(), line);
		rows.push({
			line,
			identifier,
			passwordHash: hash < 0 ? "" : (f[hash] ?? "").trim(),
		});
	});
	return { rows, problems };
}

// toCSV writes rows back out, quoting what needs it: the failed rows go
// back to the admin to fix and import again.
export const toCSV = (rows: string[][]) =>
	rows
		.map((r) =>
			r
				.map((v) => (/[",\r\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v))
				.join(","),
		)
		.join("\n");
