import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  createACMEServer,
  updateACMEServer,
  ACMEServerCreateParams,
} from "@/queries";
import { ACMEServerEntry, getErrorMessage } from "@/types";
import { ChangeEvent, useEffect, useState } from "react";
import {
  Button,
  Input,
  Panel,
  Form,
  Notification,
  Col,
  useToastNotification,
} from "@canonical/react-components";

type AsideProps = {
  setAsideOpen: () => void;
  editingServer: ACMEServerEntry | null;
};

type EnvVarPair = { key: string; value: string };

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
  const [formError, setFormError] = useState("");

  useEffect(() => {
    if (editingServer) {
      setName(editingServer.name);
      setDirectoryURL(editingServer.directory_url);
      setEmail(editingServer.email);
      setDNSProvider(editingServer.dns_provider);
      const existingVars = editingServer.env_var_keys.map((key) => ({
        key,
        value: "",
      }));
      setEnvVars(
        existingVars.length > 0 ? existingVars : [{ key: "", value: "" }],
      );
    } else {
      resetForm();
    }
  }, [editingServer]);

  const resetForm = () => {
    setName("");
    setDirectoryURL("");
    setEmail("");
    setDNSProvider("");
    setEnvVars([{ key: "", value: "" }]);
    setFormError("");
  };

  const buildEnvVarsMap = (): Record<string, string> => {
    const map: Record<string, string> = {};
    for (const pair of envVars) {
      if (pair.key.trim()) {
        map[pair.key.trim()] = pair.value;
      }
    }
    return map;
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
    const envVarsMap = buildEnvVarsMap();

    if (isEditing && editingServer) {
      const existingKeysWithoutValues = editingServer.env_var_keys.filter(
        (key) => !(key in envVarsMap),
      );
      if (existingKeysWithoutValues.length > 0) {
        const confirmed = window.confirm(
          `The following provider variables will be removed:\n${existingKeysWithoutValues.join(", ")}\n\nContinue?`,
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
      updateMutation.mutate({ ...params, id: editingServer!.id.toString() });
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
                key={index}
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
