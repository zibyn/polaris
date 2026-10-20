// Star is the four-pointed Polaris mark, the brand's one graphic. It takes
// its color from currentColor; in the Polaris color it's text-star.
export function Star({ className }: { className?: string }) {
	return (
		<svg viewBox="0 0 24 24" aria-hidden="true" className={className}>
			<path
				fill="currentColor"
				d="M12 1.5c.7 6.2 4.3 9.8 10.5 10.5-6.2.7-9.8 4.3-10.5 10.5-.7-6.2-4.3-9.8-10.5-10.5C7.7 11.3 11.3 7.7 12 1.5Z"
			/>
		</svg>
	);
}
