import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCSV, readImport, toCSV } from "./import.ts";

const argon =
	"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

test("quoted fields keep their commas, quotes and newlines", () => {
	assert.deepEqual(parseCSV(`a,"b,c","d""e"\r\n"x\ny",z`), [
		["a", "b,c", 'd"e'],
		["x\ny", "z"],
	]);
	assert.deepEqual(parseCSV("a,b\n"), [["a", "b"]]);
});

test("rows read by their header, in any order", () => {
	const r = readImport(
		`﻿password_hash,Identifier\n"${argon}",a@x.com\n,13800001234\n\n`,
	);
	assert.ok("rows" in r);
	assert.deepEqual(r.rows, [
		{ line: 2, identifier: "a@x.com", passwordHash: argon },
		{ line: 3, identifier: "13800001234", passwordHash: "" },
	]);
	assert.deepEqual(r.problems, []);
});

test("missing and repeated identifiers are problems, not rows", () => {
	const r = readImport("identifier\na@x.com\n\nA@x.com\n ,\nb");
	assert.ok("rows" in r);
	assert.deepEqual(
		r.rows.map((x) => x.identifier),
		["a@x.com", "b"],
	);
	assert.deepEqual(r.problems, [{ line: 4, message: "与第 2 行重复" }]);
});

test("a file without the identifier column is turned down", () => {
	assert.ok("error" in readImport("email\na@x.com"));
	assert.ok("error" in readImport(""));
});

test("failed rows round-trip through toCSV", () => {
	const rows = [
		["identifier", "password_hash"],
		["a@x.com", argon],
	];
	assert.deepEqual(parseCSV(toCSV(rows)), rows);
});
