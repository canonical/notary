export type OIDCProviderChoice = {
	name: string;
	/** Label shown to the user, empty when there is only one provider to pick. */
	label: string;
	loginURL: string;
};

/**
 * oidcProviders turns the provider names reported by /status into the choices
 * offered on the login and initialize pages. A deployment with a single
 * provider keeps the original unlabelled button, so nothing changes for it.
 */
export function oidcProviders(names?: string[]): OIDCProviderChoice[] {
	if (!names || names.length === 0) {
		return [{ name: "", label: "", loginURL: "/api/v1/oauth/login" }];
	}
	const showLabels = names.length > 1;
	return names.map((name) => ({
		name,
		label: showLabels ? name : "",
		loginURL: `/api/v1/oauth/login?provider=${encodeURIComponent(name)}`,
	}));
}
