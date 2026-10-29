// A Session's User-Agent as a short device label (docs/spec/consoles.md
// 「设备与会话」). The server keeps the raw string; reading it is ours.

// Order matters: Edge and Opera also say Chrome, Chrome also says Safari.
const browsers: [RegExp, string][] = [
	[/Edg(e|A|iOS)?\//, "Edge"],
	[/OPR\//, "Opera"],
	[/Firefox\/|FxiOS\//, "Firefox"],
	[/Chrome\/|CriOS\//, "Chrome"],
	[/Version\/.*Safari\//, "Safari"],
];

// iOS and Android before macOS and Linux: their UAs mention both.
const systems: [RegExp, string][] = [
	[/iPhone|iPad|iPod/, "iOS"],
	[/Android/, "Android"],
	[/Windows/, "Windows"],
	[/CrOS/, "ChromeOS"],
	[/Macintosh|Mac OS X/, "macOS"],
	[/Linux/, "Linux"],
];

const maxRaw = 40;

export function deviceLabel(userAgent: string | undefined): string {
	if (!userAgent) return "未知设备";
	// The Polaris KMP SDK: <App>/<version> (<system> <version>; <model>) Polaris-KMP/<version>
	const kmp = userAgent.match(/\(([^;()]+); ([^()]+)\) Polaris-KMP\//);
	if (kmp) return `${kmp[2]} · ${kmp[1]}`;
	const browser = browsers.find(([re]) => re.test(userAgent))?.[1];
	const system = systems.find(([re]) => re.test(userAgent))?.[1];
	if (browser) return system ? `${browser} · ${system}` : browser;
	return userAgent.length > maxRaw
		? `${userAgent.slice(0, maxRaw)}…`
		: userAgent;
}
