import {
	Button,
	Col,
	Form,
	Input,
	Notification,
	Panel,
	Select,
	Textarea,
	useToastNotification,
} from "@canonical/react-components";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, useCallback, useEffect, useState } from "react";
import {
	type ACMEServerCreateParams,
	createACMEServer,
	updateACMEServer,
} from "@/utils/queries";
import { type ACMEServerEntry, getErrorMessage } from "@/utils/types";

type AsideProps = {
	setAsideOpen: () => void;
	editingServer: ACMEServerEntry | null;
};

type EnvVarPair = { key: string; value: string };

const EAB_KID = "NOTARY_ACME_EAB_KID";
const EAB_HMAC = "NOTARY_ACME_EAB_HMAC";
const CA_CERTIFICATES = "NOTARY_ACME_CA_CERTIFICATES";
const DNS_PROPAGATION_WAIT = "NOTARY_ACME_DNS_PROPAGATION_WAIT";
const DNS_NAMESERVERS = "NOTARY_ACME_DNS_NAMESERVERS";
const DISABLE_CNAME_SUPPORT = "NOTARY_ACME_DISABLE_CNAME_SUPPORT";
const advancedSettingKeys = new Set([
	EAB_KID,
	EAB_HMAC,
	CA_CERTIFICATES,
	DNS_PROPAGATION_WAIT,
	DNS_NAMESERVERS,
	DISABLE_CNAME_SUPPORT,
]);

export default function ACMEServersAsidePanel({
	setAsideOpen,
	editingServer,
}: AsideProps) {
	const queryClient = useQueryClient();
	const toastNotify = useToastNotification();
	const isEditing = editingServer !== null;
	const [name, setName] = useState("");
	const [directoryURL, setDirectoryURL] = useState("");
	const [email, setEmail] = useState("");
	const [dnsProvider, setDNSProvider] = useState("");
	const [envVars, setEnvVars] = useState<EnvVarPair[]>([
		{ key: "", value: "" },
	]);
	const [eabKID, setEABKID] = useState("");
	const [eabHMAC, setEABHMAC] = useState("");
	const [caCertificates, setCACertificates] = useState("");
	const [dnsPropagationWait, setDNSPropagationWait] = useState("");
	const [dnsNameservers, setDNSNameservers] = useState("");
	const [disableCNAMESupport, setDisableCNAMESupport] = useState("");
	const [removedAdvancedSettings, setRemovedAdvancedSettings] = useState<
		Set<string>
	>(new Set());
	const [formError, setFormError] = useState("");
	const existingAdvancedSettings = new Set(
		editingServer?.env_var_keys.filter((key) => advancedSettingKeys.has(key)) ??
			[],
	);

	const resetForm = useCallback(() => {
		setName("");
		setDirectoryURL("");
		setEmail("");
		setDNSProvider("");
		setEnvVars([{ key: "", value: "" }]);
		setEABKID("");
		setEABHMAC("");
		setCACertificates("");
		setDNSPropagationWait("");
		setDNSNameservers("");
		setDisableCNAMESupport("");
		setRemovedAdvancedSettings(new Set());
		setFormError("");
	}, []);

	useEffect(() => {
		if (editingServer) {
			setName(editingServer.name);
			setDirectoryURL(editingServer.directory_url);
			setEmail(editingServer.email);
			setDNSProvider(editingServer.dns_provider);
			const existingVars = editingServer.env_var_keys
				.filter((key: string) => !advancedSettingKeys.has(key))
				.map((key: string) => ({ key, value: "" }));
			setEnvVars(
				existingVars.length > 0 ? existingVars : [{ key: "", value: "" }],
			);
			setEABKID("");
			setEABHMAC("");
			setCACertificates("");
			setDNSPropagationWait("");
			setDNSNameservers("");
			setDisableCNAMESupport("");
			setRemovedAdvancedSettings(new Set());
		} else {
			resetForm();
		}
	}, [editingServer, resetForm]);

	const buildEnvVarsMap = (): Record<string, string> => {
		const map: Record<string, string> = {};
		for (const pair of envVars) {
			if (pair.key.trim()) {
				map[pair.key.trim()] = pair.value;
			}
		}
		for (const key of existingAdvancedSettings) {
			if (!removedAdvancedSettings.has(key)) {
				map[key] = "";
			}
		}
		const advancedValues = {
			[EAB_KID]: eabKID,
			[EAB_HMAC]: eabHMAC,
			[CA_CERTIFICATES]: caCertificates,
			[DNS_PROPAGATION_WAIT]: dnsPropagationWait,
			[DNS_NAMESERVERS]: dnsNameservers,
			[DISABLE_CNAME_SUPPORT]: disableCNAMESupport,
		};
		for (const [key, value] of Object.entries(advancedValues)) {
			if (value !== "" && !removedAdvancedSettings.has(key)) {
				map[key] = value;
			}
		}
		return map;
	};

	const setAdvancedSettingsRemoved = (keys: string[], removed: boolean) => {
		setRemovedAdvancedSettings((previous) => {
			const next = new Set(previous);
			for (const key of keys) {
				if (removed) {
					next.add(key);
				} else {
					next.delete(key);
				}
			}
			return next;
		});
	};

	const addEnvVar = () => {
		setEnvVars((prev) => [...prev, { key: "", value: "" }]);
	};

	const removeEnvVar = (index: number) => {
		setEnvVars((prev) => prev.filter((_, i) => i !== index));
	};

	const updateEnvVar = (
		index: number,
		field: "key" | "value",
		value: string,
	) => {
		setEnvVars((prev) =>
			prev.map((pair, i) => (i === index ? { ...pair, [field]: value } : pair)),
		);
	};

	const createMutation = useMutation({
		mutationFn: createACMEServer,
		onSuccess: () => {
			resetForm();
			setAsideOpen();
			void queryClient.invalidateQueries({ queryKey: ["acme_servers"] });
			toastNotify.success(
				"The ACME server was added successfully.",
				undefined,
				"ACME server added",
			);
		},
		onError: (e: Error) => {
			setFormError(getErrorMessage(e));
		},
	});

	const updateMutation = useMutation({
		mutationFn: updateACMEServer,
		onSuccess: () => {
			setAsideOpen();
			void queryClient.invalidateQueries({ queryKey: ["acme_servers"] });
			toastNotify.success(
				"The ACME server was updated successfully.",
				undefined,
				"ACME server updated",
			);
		},
		onError: (e: Error) => {
			setFormError(getErrorMessage(e));
		},
	});

	const isPending = createMutation.isPending || updateMutation.isPending;

	const canSubmit =
		name.trim() !== "" &&
		directoryURL.trim() !== "" &&
		email.trim() !== "" &&
		dnsProvider.trim() !== "";

	const handleSubmit = () => {
		const reservedProviderSetting = envVars.find((pair) =>
			advancedSettingKeys.has(pair.key.trim()),
		);
		if (reservedProviderSetting) {
			setFormError(
				`${reservedProviderSetting.key.trim()} must be configured under Advanced ACME settings.`,
			);
			return;
		}

		const hasEABKID =
			eabKID !== "" ||
			(existingAdvancedSettings.has(EAB_KID) &&
				!removedAdvancedSettings.has(EAB_KID));
		const hasEABHMAC =
			eabHMAC !== "" ||
			(existingAdvancedSettings.has(EAB_HMAC) &&
				!removedAdvancedSettings.has(EAB_HMAC));
		if (hasEABKID !== hasEABHMAC) {
			setFormError("EAB key ID and HMAC must be configured together.");
			return;
		}

		const envVarsMap = buildEnvVarsMap();

		if (isEditing && editingServer) {
			const existingKeysWithoutValues = editingServer.env_var_keys.filter(
				(key: string) => !(key in envVarsMap),
			);
			if (existingKeysWithoutValues.length > 0) {
				const confirmed = window.confirm(
					`The following ACME settings will be removed:\n${existingKeysWithoutValues.join(", ")}\n\nContinue?`,
				);
				if (!confirmed) {
					return;
				}
			}
		}

		const params: ACMEServerCreateParams = {
			name: name.trim(),
			directory_url: directoryURL.trim(),
			email: email.trim(),
			dns_provider: dnsProvider.trim(),
			env_vars: envVarsMap,
		};
		if (isEditing) {
			updateMutation.mutate({ ...params, id: editingServer.id.toString() });
		} else {
			createMutation.mutate(params);
		}
	};

	return (
		<Panel
			title={isEditing ? "Edit ACME Server" : "Add ACME Server"}
			controls={
				<Button onClick={setAsideOpen} hasIcon>
					<i className="p-icon--close" />
				</Button>
			}
		>
			<Form stacked>
				<div className="p-form__group row">
					<Input
						label="Name"
						id="acme-name"
						type="text"
						value={name}
						onChange={(e: ChangeEvent<HTMLInputElement>) =>
							setName(e.target.value)
						}
						help="A friendly display name for this ACME server configuration."
						stacked
						required
					/>
					<Input
						label="Directory URL"
						id="acme-directory-url"
						type="url"
						value={directoryURL}
						onChange={(e: ChangeEvent<HTMLInputElement>) =>
							setDirectoryURL(e.target.value)
						}
						help="The ACME directory URL, e.g. https://acme-v02.api.letsencrypt.org/directory"
						stacked
						required
					/>
					<Input
						label="Email"
						id="acme-email"
						type="email"
						value={email}
						onChange={(e: ChangeEvent<HTMLInputElement>) =>
							setEmail(e.target.value)
						}
						help="The email used for ACME account registration and notifications."
						stacked
						required
					/>
					<Input
						label="DNS Provider"
						id="acme-dns-provider"
						type="text"
						value={dnsProvider}
						onChange={(e: ChangeEvent<HTMLInputElement>) =>
							setDNSProvider(e.target.value)
						}
						help="The LEGO DNS provider name, e.g. cloudflare, hetzner, route53."
						stacked
						required
					/>
				</div>

				<div className="p-form__group row">
					<fieldset>
						<legend>
							Provider Environment Variables
							{isEditing && (
								<small style={{ display: "block", color: "#666" }}>
									Existing keys are shown with empty values. Update values as
									needed, or leave empty to keep the existing credential.
								</small>
							)}
						</legend>
						{envVars.map((pair, index) => (
							<div
								key={`env-${pair.key || index}`}
								style={{ display: "flex", gap: "8px", marginBottom: "8px" }}
							>
								<Input
									id={`env-key-${index}`}
									type="text"
									placeholder="Key (e.g. CF_DNS_API_TOKEN)"
									value={pair.key}
									onChange={(e: ChangeEvent<HTMLInputElement>) =>
										updateEnvVar(index, "key", e.target.value)
									}
									style={{ flex: 1 }}
								/>
								<Input
									id={`env-value-${index}`}
									type="password"
									placeholder="Value"
									value={pair.value}
									onChange={(e: ChangeEvent<HTMLInputElement>) =>
										updateEnvVar(index, "value", e.target.value)
									}
									style={{ flex: 1 }}
								/>
								{envVars.length > 1 && (
									<Button
										hasIcon
										onClick={(e) => {
											e.preventDefault();
											removeEnvVar(index);
										}}
										appearance="base"
										title="Remove"
									>
										<i className="p-icon--delete" />
									</Button>
								)}
							</div>
						))}
						<Button
							onClick={(e) => {
								e.preventDefault();
								addEnvVar();
							}}
							appearance="base"
							hasIcon
							small
						>
							<i className="p-icon--plus" /> <span>Add variable</span>
						</Button>
					</fieldset>
				</div>

				<div className="p-form__group row">
					<fieldset>
						<legend>
							Advanced ACME settings
							{isEditing && (
								<small style={{ display: "block", color: "#666" }}>
									Leave values empty to keep existing settings.
								</small>
							)}
						</legend>
						<Input
							label="EAB key ID"
							id="acme-eab-kid"
							type="password"
							value={eabKID}
							onChange={(e: ChangeEvent<HTMLInputElement>) =>
								setEABKID(e.target.value)
							}
							disabled={
								removedAdvancedSettings.has(EAB_KID) ||
								removedAdvancedSettings.has(EAB_HMAC)
							}
							stacked
						/>
						<Input
							label="EAB HMAC"
							id="acme-eab-hmac"
							type="password"
							value={eabHMAC}
							onChange={(e: ChangeEvent<HTMLInputElement>) =>
								setEABHMAC(e.target.value)
							}
							disabled={
								removedAdvancedSettings.has(EAB_KID) ||
								removedAdvancedSettings.has(EAB_HMAC)
							}
							stacked
						/>
						{(existingAdvancedSettings.has(EAB_KID) ||
							existingAdvancedSettings.has(EAB_HMAC)) && (
							<label className="p-checkbox">
								<input
									className="p-checkbox__input"
									type="checkbox"
									checked={
										removedAdvancedSettings.has(EAB_KID) ||
										removedAdvancedSettings.has(EAB_HMAC)
									}
									onChange={(e: ChangeEvent<HTMLInputElement>) =>
										setAdvancedSettingsRemoved(
											[EAB_KID, EAB_HMAC],
											e.target.checked,
										)
									}
								/>
								<span className="p-checkbox__label">
									Remove existing EAB credentials
								</span>
							</label>
						)}

						<Textarea
							label="ACME CA certificates"
							id="acme-ca-certificates"
							value={caCertificates}
							onChange={(e: ChangeEvent<HTMLTextAreaElement>) =>
								setCACertificates(e.target.value)
							}
							disabled={removedAdvancedSettings.has(CA_CERTIFICATES)}
							help="Optional PEM CA bundle added to the system trust roots."
							stacked
						/>
						{existingAdvancedSettings.has(CA_CERTIFICATES) && (
							<label className="p-checkbox">
								<input
									className="p-checkbox__input"
									type="checkbox"
									checked={removedAdvancedSettings.has(CA_CERTIFICATES)}
									onChange={(e: ChangeEvent<HTMLInputElement>) =>
										setAdvancedSettingsRemoved(
											[CA_CERTIFICATES],
											e.target.checked,
										)
									}
								/>
								<span className="p-checkbox__label">
									Remove existing CA certificates
								</span>
							</label>
						)}

						<Input
							label="DNS propagation wait (seconds)"
							id="acme-dns-propagation-wait"
							type="number"
							min={1}
							value={dnsPropagationWait}
							onChange={(e: ChangeEvent<HTMLInputElement>) =>
								setDNSPropagationWait(e.target.value)
							}
							disabled={removedAdvancedSettings.has(DNS_PROPAGATION_WAIT)}
							stacked
						/>
						{existingAdvancedSettings.has(DNS_PROPAGATION_WAIT) && (
							<label className="p-checkbox">
								<input
									className="p-checkbox__input"
									type="checkbox"
									checked={removedAdvancedSettings.has(DNS_PROPAGATION_WAIT)}
									onChange={(e: ChangeEvent<HTMLInputElement>) =>
										setAdvancedSettingsRemoved(
											[DNS_PROPAGATION_WAIT],
											e.target.checked,
										)
									}
								/>
								<span className="p-checkbox__label">
									Remove existing propagation wait
								</span>
							</label>
						)}

						<Input
							label="DNS nameservers"
							id="acme-dns-nameservers"
							type="text"
							value={dnsNameservers}
							onChange={(e: ChangeEvent<HTMLInputElement>) =>
								setDNSNameservers(e.target.value)
							}
							disabled={removedAdvancedSettings.has(DNS_NAMESERVERS)}
							help="Comma-separated resolver IP addresses with optional ports."
							stacked
						/>
						{existingAdvancedSettings.has(DNS_NAMESERVERS) && (
							<label className="p-checkbox">
								<input
									className="p-checkbox__input"
									type="checkbox"
									checked={removedAdvancedSettings.has(DNS_NAMESERVERS)}
									onChange={(e: ChangeEvent<HTMLInputElement>) =>
										setAdvancedSettingsRemoved(
											[DNS_NAMESERVERS],
											e.target.checked,
										)
									}
								/>
								<span className="p-checkbox__label">
									Remove existing nameservers
								</span>
							</label>
						)}

						<Select
							label="Disable CNAME support"
							id="acme-disable-cname-support"
							value={disableCNAMESupport}
							onChange={(e: ChangeEvent<HTMLSelectElement>) =>
								setDisableCNAMESupport(e.target.value)
							}
							disabled={removedAdvancedSettings.has(DISABLE_CNAME_SUPPORT)}
							options={[
								{
									label: isEditing ? "Keep existing" : "Use LEGO default",
									value: "",
								},
								{ label: "Yes", value: "true" },
								{ label: "No", value: "false" },
							]}
							stacked
						/>
						{existingAdvancedSettings.has(DISABLE_CNAME_SUPPORT) && (
							<label className="p-checkbox">
								<input
									className="p-checkbox__input"
									type="checkbox"
									checked={removedAdvancedSettings.has(DISABLE_CNAME_SUPPORT)}
									onChange={(e: ChangeEvent<HTMLInputElement>) =>
										setAdvancedSettingsRemoved(
											[DISABLE_CNAME_SUPPORT],
											e.target.checked,
										)
									}
								/>
								<span className="p-checkbox__label">
									Remove existing CNAME setting
								</span>
							</label>
						)}
					</fieldset>
				</div>

				{formError && (
					<div className="p-form__group row">
						<Notification severity="negative" title="Error">
							{formError}
						</Notification>
					</div>
				)}

				<div className="p-form__group row">
					<Col size={12}>
						{isPending ? (
							<Button appearance="positive" disabled hasIcon>
								<i className="p-icon--spinner u-animation--spin" />
							</Button>
						) : (
							<Button
								appearance="positive"
								disabled={!canSubmit}
								onClick={(e) => {
									e.preventDefault();
									handleSubmit();
								}}
							>
								{isEditing ? "Save Changes" : "Add ACME Server"}
							</Button>
						)}
					</Col>
				</div>
			</Form>
		</Panel>
	);
}
