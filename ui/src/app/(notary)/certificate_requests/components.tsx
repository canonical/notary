import {
  Dispatch,
  SetStateAction,
  useState,
  ChangeEvent,
  useEffect,
} from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { csrMatchesCertificate, splitBundle, validateBundle } from "@/utils";
import { postCertToID } from "@/queries";
import {
  Button,
  Input,
  Textarea,
  Form,
  Modal,
  Icon,
} from "@canonical/react-components";
import { useAuth } from "@/hooks/useAuth";

interface SubmitCertificateModalProps {
  id: string;
  csr: string;
  cert: string;
  setFormOpen: Dispatch<SetStateAction<boolean>>;
}

export function SubmitCertificateModal({
  id,
  csr,
  cert,
  setFormOpen,
}: SubmitCertificateModalProps) {
  const auth = useAuth();
  const [errorText, setErrorText] = useState<string>("");
  const [certificatePEMString, setCertificatePEMString] =
    useState<string>(cert);
  const [validationErrorText, setValidationErrorText] = useState<string>("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: postCertToID,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["csrs"] });
      setErrorText("");
      setFormOpen(false);
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });

  const handleTextChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
    setCertificatePEMString(event.target.value);
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e: ProgressEvent<FileReader>) => {
        if (e.target?.result) {
          setCertificatePEMString(
            typeof e.target.result === "string" ? e.target.result : "",
          );
        }
      };
      reader.readAsText(file);
    }
  };

  useEffect(() => {
    const validateCertificate = async () => {
      try {
        const certs = splitBundle(certificatePEMString);
        if (certs.length < 2) {
          setValidationErrorText("Bundle with 2 certificates required");
          return;
        }
        if (!csrMatchesCertificate(csr, certs[0])) {
          setValidationErrorText("Certificate does not match request");
          return;
        }
        const validationMessage = await validateBundle(certificatePEMString);
        if (validationMessage !== "") {
          setValidationErrorText(
            "Bundle validation failed: " + validationMessage,
          );
          return;
        }
      } catch {
        setValidationErrorText("A certificate is invalid");
        return;
      }
      setValidationErrorText("");
    };
    void validateCertificate();
  }, [csr, certificatePEMString]);

  return (
    <Modal
      title="Submit Certificate"
      buttonRow={
        <>
          <Button
            onClick={() =>
              mutation.mutate({
                id,
                authToken: auth.user ? auth.user.authToken : "",
                cert: certificatePEMString,
              })
            }
            appearance="positive"
            disabled={validationErrorText !== "" || certificatePEMString === ""}
          >
            Submit
          </Button>
          <Button onMouseDown={() => setFormOpen(false)}>Cancel</Button>
        </>
      }
    >
      <Form stacked={true}>
        <div className="p-form__group row">
          <Textarea
            name="textarea"
            id="csr-textarea"
            label="Enter or upload the Certificate in PEM format below"
            placeholder="-----BEGIN CERTIFICATE-----"
            rows={10}
            onChange={handleTextChange}
            value={certificatePEMString}
            error={validationErrorText || errorText}
          />
        </div>
        <div className="p-form__group row">
          <Input
            type="file"
            name="upload"
            accept=".pem,.crt"
            onChange={handleFileChange}
          />
        </div>
      </Form>
    </Modal>
  );
}

export function SuccessNotification({
  successMessage,
}: {
  successMessage: string;
}) {
  const style = {
    display: "inline",
  };
  return (
    <p style={style}>
      <Icon name="success" />
      {successMessage}
    </p>
  );
}
