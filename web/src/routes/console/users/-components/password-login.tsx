import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Alert, AlertDescription } from "#/components/ui/alert";
import { policyQuery } from "#/routes/console/-settings/policy";

// usePasswordLoginOff: 创建用户 hands over a password, so with 密码登录 off
// there is nothing to create (ADR 0016) and the entry says why. Reading it
// takes config:read, which every built-in Role holding users:write also
// holds; a reader without it gets no answer here, and the server turns the
// create down in words instead.
export function usePasswordLoginOff() {
	const { data, error } = useQuery({ ...policyQuery, retry: false });
	return !error && data?.passwordLogin === "off";
}

// PasswordLoginNotice is why 创建用户 is disabled. detail is the extra
// sentence 创建页 adds: what the account you'd create is missing
// (依赖提示 #21).
export function PasswordLoginNotice({ detail }: { detail?: string }) {
	return (
		<Alert variant="warning">
			<AlertDescription>
				请先在登录方式里开启密码登录。{detail}{" "}
				<Link to="/console/settings" search={{ tab: "login" }}>
					去开启密码登录
				</Link>
			</AlertDescription>
		</Alert>
	);
}
