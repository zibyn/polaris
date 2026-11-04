import { toast } from "sonner";
import { failed } from "#/components/form";
import { Button } from "#/components/ui/button";

// copyText copies value and says in a toast whether it did.
export const copyText = (value: string) =>
	navigator.clipboard
		.writeText(value)
		.then(() => toast.success("已复制"), failed("复制失败"));

// CopyButton copies value and says whether it did.
export function CopyButton({ value }: { value: string }) {
	return (
		<Button
			type="button"
			variant="outline"
			size="sm"
			onClick={() => copyText(value)}
		>
			复制
		</Button>
	);
}
