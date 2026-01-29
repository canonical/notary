import { useMutation, useQueryClient } from "@tanstack/react-query";
import { csrIsValid } from "@/utils";
import { postCSR } from "@/queries";
import {
  ChangeEvent,
  useState,
  useEffect,
  Dispatch,
  SetStateAction,
} from "react";
import {
  Textarea,
  Button,
  Input,
  Panel,
  Form,
} from "@canonical/react-components";

type AsideProps = {
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
};

export default function CertificateRequestsAsidePanel({
  setAsideOpen,
}: AsideProps): JSX.Element {
  const [errorText, setErrorText] = useState<string>("");
  const [CSRPEMString, setCSRPEMString] = useState<string>("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: postCSR,
    onSuccess: () => {
      setErrorText("");
      setAsideOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["csrs"] });
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });

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

  const handleSubmit = () => {
    mutation.mutate({
      csr: CSRPEMString,
    });
  };

  return (
    <Panel
      title="Add a New Certificate Request"
      controls={
        <Button onClick={() => setAsideOpen(false)} hasIcon>
          <i className="p-icon--close" />
        </Button>
      }
    >
      <Form stacked={true}>
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
        <div className="p-form__group row">
          <Button
            type="button"
            appearance="positive"
            name="submit"
            disabled={!csrIsValid(CSRPEMString)}
            onClick={handleSubmit}
          >
            Submit
          </Button>
        </div>
      </Form>
    </Panel>
  );
}
