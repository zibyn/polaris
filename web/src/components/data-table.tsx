// A sorted, fuzzy-searchable table for lists that arrive in one response
// (Applications, API resources, Providers). The server-paginated lists
// (Users, audit) keep their own filters and load-more.

import { rankItem } from "@tanstack/match-sorter-utils";
import {
	type ColumnDef,
	columnFilteringFeature,
	createFilteredRowModel,
	createSortedRowModel,
	type FilterFn,
	globalFilteringFeature,
	type Row,
	type RowData,
	rowSortingFeature,
	sortFn_alphanumeric,
	sortFn_basic,
	tableFeatures,
	useTable,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { ReactNode } from "react";
import { Input } from "#/components/ui/input";
import { Separator } from "#/components/ui/separator";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "#/components/ui/table";

// features is shared by every table and by the pages' column helpers.
export const features = tableFeatures({
	columnFilteringFeature,
	globalFilteringFeature,
	rowSortingFeature,
	filteredRowModel: createFilteredRowModel(),
	sortedRowModel: createSortedRowModel(),
	sortFns: {
		alphanumeric: sortFn_alphanumeric,
		basic: sortFn_basic,
	},
});

// fuzzyFilter ranks a query against every globally filterable column, so
// "gthub" still finds "GitHub".
function fuzzyFilter<TData extends RowData>(
	row: Row<typeof features, TData>,
	columnId: string,
	value: string,
): boolean {
	return rankItem(row.getValue(columnId), value).passed;
}

export type DataTableColumn<TData extends RowData> = ColumnDef<
	typeof features,
	TData,
	// biome-ignore lint/suspicious/noExplicitAny: column values differ per table
	any
>;

export function DataTable<TData extends RowData>({
	data,
	columns,
	filterPlaceholder,
	empty = "没有数据",
}: {
	data: TData[];
	columns: DataTableColumn<TData>[];
	filterPlaceholder?: string;
	empty?: ReactNode;
}) {
	const table = useTable({
		features,
		data,
		columns,
		globalFilterFn: fuzzyFilter as FilterFn<typeof features, TData>,
	});
	const filter = (table.state.globalFilter ?? "") as string;
	const rows = table.getRowModel().rows;
	return (
		<div className="flex flex-col gap-3">
			{filterPlaceholder && (
				<>
					<Input
						type="search"
						aria-label={filterPlaceholder}
						placeholder={filterPlaceholder}
						value={filter}
						onChange={(e) => table.setGlobalFilter(e.target.value)}
						className="max-w-sm"
					/>
					<Separator />
				</>
			)}
			<Table>
				<TableHeader>
					{table.getHeaderGroups().map((group) => (
						<TableRow key={group.id}>
							{group.headers.map((header) => (
								<TableHead
									key={header.id}
									aria-sort={
										header.column.getIsSorted() === "asc"
											? "ascending"
											: header.column.getIsSorted() === "desc"
												? "descending"
												: undefined
									}
								>
									{header.isPlaceholder ? null : header.column.getCanSort() ? (
										<button
											type="button"
											className="-mx-1 flex cursor-pointer items-center gap-1 rounded px-1 select-none hover:text-foreground"
											onClick={header.column.getToggleSortingHandler()}
										>
											<table.FlexRender header={header} />
											<SortIcon sorted={header.column.getIsSorted()} />
										</button>
									) : (
										<table.FlexRender header={header} />
									)}
								</TableHead>
							))}
						</TableRow>
					))}
				</TableHeader>
				<TableBody>
					{rows.length === 0 ? (
						<TableRow>
							<TableCell
								colSpan={columns.length}
								className="py-8 text-center text-muted-foreground"
							>
								{empty}
							</TableCell>
						</TableRow>
					) : (
						rows.map((row) => (
							<TableRow key={row.id}>
								{row.getAllCells().map((cell) => (
									<TableCell key={cell.id}>
										<table.FlexRender cell={cell} />
									</TableCell>
								))}
							</TableRow>
						))
					)}
				</TableBody>
			</Table>
		</div>
	);
}

function SortIcon({ sorted }: { sorted: false | "asc" | "desc" }) {
	const Icon =
		sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ArrowUpDown;
	return <Icon className="size-3.5 text-muted-foreground" aria-hidden="true" />;
}
