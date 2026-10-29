import { UserRound } from "lucide-react";
import { Avatar, AvatarFallback, AvatarImage } from "#/components/ui/avatar";
import { avatarInitial } from "#/lib/users";

// UserAvatar is a User's avatar picture, else their initial on the primary
// tint; one with no Identifier gets the person icon. sm sits in a row, lg
// heads a page.
export function UserAvatar({
	name,
	picture,
	size = "sm",
}: {
	name?: string;
	picture?: string;
	size?: "sm" | "lg";
}) {
	return (
		<Avatar size={size}>
			{picture && <AvatarImage src={picture} alt="" />}
			<AvatarFallback className="bg-primary-soft font-medium text-primary-ink">
				{name ? avatarInitial(name) : <UserRound className="size-3.5" />}
			</AvatarFallback>
		</Avatar>
	);
}
