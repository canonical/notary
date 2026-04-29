"use client";

import { postCSR } from "@/queries";
import NotaryAppAside from "@/components/NotaryAsidePanel";
import { csrIsValid } from "@/utils";
import {
  ChangeEvent,
  useState,
  useEffect,
  Dispatch,
  SetStateAction,
  ReactElement,
} from "react";
import {
  Textarea,
  Button,
  Input,
  Form,
  Col,
} from "@canonical/react-components";

type CSRAsideProps = {
  asideIsOpen: boolean;
  setAsideIsOpen: Dispatch<SetStateAction<boolean>>;
};

export default function CertificateRequestsAside({
  asideIsOpen,
  setAsideIsOpen,
}: CSRAsideProps): ReactElement {
  const [errorText, setErrorText] = useState<string>("");
  const [CSRPEMString, setCSRPEMString] = useState<string>("");

  useEffect(() => {
    if (CSRPEMString && !csrIsValid(CSRPEMString)) {
      setErrorText("Invalid CSR format");
    } else {
      setErrorText("");
    }
  }, [CSRPEMString]);

  const handleTextChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
    setCSRPEMString(event.target.value);
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e: ProgressEvent<FileReader>) => {
        if (e.target?.result) {
          setCSRPEMString(
            typeof e.target.result === "string" ? e.target.result : "",
          );
        }
      };
      reader.readAsText(file);
    }
  };

  return (
    <NotaryAppAside
      // Aside panel controls
      asidePanelTitle="Create Certificate Request"
      asidePanelIsOpen={asideIsOpen}
      setAsidePanelIsOpen={setAsideIsOpen}
      // Aside panel mutation props
      formData={{ csr: CSRPEMString }}
      mutationFn={postCSR}
      invalidatedQueryKeys={["csrs"]}
      mutationSuccessMessageTitle="The certificate request was created successfully."
      mutationErrorMessageTitle="Failed to create the certificate request."
      // Submit button
      renderSubmitButton={(handleSubmit) => {
        return (
          <Col size={12}>
            <Button
              type="button"
              appearance="positive"
              name="submit"
              disabled={!csrIsValid(CSRPEMString)}
              onClick={handleSubmit}
            >
              Submit
            </Button>
          </Col>
        );
      }}
    >
      <div className="p-form__group row">
        <Textarea
          name="textarea"
          id="csr-textarea"
          label="Enter or upload the CSR in PEM format below"
          placeholder="-----BEGIN CERTIFICATE REQUEST-----"
          rows={10}
          onChange={handleTextChange}
          value={CSRPEMString}
          error={errorText}
        />
      </div>
      <div className="p-form__group row">
        <Input
          type="file"
          name="upload"
          accept=".pem,.csr"
          onChange={handleFileChange}
        />
      </div>
    </NotaryAppAside>
  );
}
