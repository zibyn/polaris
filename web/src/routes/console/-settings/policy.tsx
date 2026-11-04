import { revalidateLogic, useForm } from "@tanstack/react-form";
import { useSuspenseQuery } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { FormField } from "#/components/form";
import { Input } from "#/components/ui/input";
import type { Policy } from "#/lib/console-api";
import { numberSchema, type PolicyPlan, planPolicySave } from "#/lib/login";
import { policyQuery, useSavePolicy } from "#/lib/queries";
import { ConfirmDialog } from "#/routes/console/-components/confirm-dialog";
import { SaveBar, Section } from "#/routes/console/-components/section";
import { useCan } from "#/routes/console/route";

export function usePolicy() {
	const can = useCan();
	const policy = useSuspenseQuery(policyQuery).data;
	return { policy, editable: can("config:write") };
}

// PolicyNumber edits one numeric setting in its own section. warning shows
// under the field as it is typed; confirm asks before saving when
// planPolicySave says the change needs a question.
type PolicyNumberProps = {
	title: string;
	field: "dailySendLimit" | "auditRetentionDays";
	label: string;
	suffix: string;
	help: string;
	min: number;
	warning?: (plan: PolicyPlan) => ReactNode;
	confirm?: {
		title: string;
		action: string;
		body: ReactNode;
	};
};

export function PolicyNumber(props: PolicyNumberProps) {
	const { policy, editable } = usePolicy();
	return <NumberForm {...props} policy={policy} editable={editable} />;
}

function NumberForm({
	policy,
	editable,
	title,
	field,
	label,
	suffix,
	help,
	min,
	warning,
	confirm,
}: PolicyNumberProps & {
	policy: Policy;
	editable: boolean;
}) {
	const save = useSavePolicy();
	const current = policy[field];
	const plan = (n: number) => planPolicySave(policy, { [field]: n });
	const [asking, setAsking] = useState<number>();
	const write = (n: number) => save.mutate({ [field]: n });
	const form = useForm({
		defaultValues: { value: String(current) },
		validationLogic: revalidateLogic(),
		validators: { onDynamic: numberSchema(min) },
		onSubmit: ({ value }) => {
			const next = Number(value.value.trim());
			if (confirm && plan(next).confirm) {
				setAsking(next);
			} else {
				write(next);
			}
		},
	});
	return (
		<Section
			title={title}
			editable={editable}
			form={form}
			footer={editable && <SaveBar save={save} />}
		>
			<form.Field name="value">
				{(f) => (
					<FormField field={f} label={label} help={help}>
						{(control) => (
							<>
								<div className="flex items-center gap-2">
									<Input
										{...control}
										type="number"
										min={min}
										className="w-32"
									/>
									<span className="text-sm">{suffix}</span>
								</div>
								{f.state.value !== "" && warning?.(plan(Number(f.state.value)))}
							</>
						)}
					</FormField>
				)}
			</form.Field>
			{confirm && (
				<ConfirmDialog
					open={asking !== undefined}
					onOpenChange={(o) => !o && setAsking(undefined)}
					title={confirm.title}
					action={confirm.action}
					onConfirm={() => asking !== undefined && write(asking)}
				>
					{confirm.body}
				</ConfirmDialog>
			)}
		</Section>
	);
}
