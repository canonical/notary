import { useMutation, useQueryClient } from "@tanstack/react-query";
import { postCA } from "@/queries";
import { getErrorMessage } from "@/types";
import {
  ChangeEvent,
  useMemo,
  useState,
  Dispatch,
  SetStateAction,
  ReactElement,
} from "react";
import {
  Button,
  Input,
  Panel,
  Form,
  Notification,
  Col,
  useToastNotification,
} from "@canonical/react-components";
import {
  validationResult,
  validateCommonName,
  validateOrganizationName,
  validateOrganizationalUnit,
  validateCountryName,
  validateStateOrProvinceName,
  validateLocalityName,
  validateNotAfter,
} from "@/validators";

type AsideProps = {
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
};

type ValidationState = {
  commonName: validationResult;
  organizationName: validationResult;
  organizationalUnit: validationResult;
  countryName: validationResult;
  stateOrProvinceName: validationResult;
  localityName: validationResult;
  notValidAfter: validationResult;
};

type Stage = "type" | "subject" | "validity" | "review";

const emptyValidation = (): validationResult => ({
  error: "",
  caution: "",
  success: "",
});

const initialValidationState = (): ValidationState => ({
  commonName: emptyValidation(),
  organizationName: emptyValidation(),
  organizationalUnit: emptyValidation(),
  countryName: emptyValidation(),
  stateOrProvinceName: emptyValidation(),
  localityName: emptyValidation(),
  notValidAfter: emptyValidation(),
});

export default function CertificateAuthoritiesAsidePanel({
  setAsideOpen,
}: AsideProps): ReactElement {
  const queryClient = useQueryClient();
  const toastNotify = useToastNotification();

  const [stage, setStage] = useState<Stage>("type");
  const [isSelfSigned, setIsSelfSigned] = useState<boolean | null>(null);

  const [commonName, setCommonName] = useState<string>("");
  const [organizationName, setOrganizationName] = useState<string>("");
  const [organizationalUnit, setOrganizationalUnit] = useState<string>("");
  const [countryName, setCountryName] = useState<string>("");
  const [stateOrProvinceName, setStateOrProvinceName] = useState<string>("");
  const [localityName, setLocalityName] = useState<string>("");
  const [notValidAfter, setNotValidAfter] = useState<string>("");
  const [validation, setValidation] = useState<ValidationState>(
    initialValidationState(),
  );
  const [formError, setFormError] = useState<string>("");

  const mutation = useMutation({
    mutationFn: postCA,
    onSuccess: () => {
      setFormError("");
      setAsideOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["cas"] });
      toastNotify.success(
        isSelfSigned
          ? "The certificate authority certificate was created successfully."
          : "The intermediate certificate authority CSR was created successfully.",
        undefined,
        isSelfSigned
          ? "Certificate authority created"
          : "Intermediate CA CSR created",
      );
    },
    onError: (e: Error) => {
      setFormError(getErrorMessage(e));
      toastNotify.failure(
        "Certificate authority creation failed",
        e,
        "Failed to create the certificate authority.",
      );
    },
  });

  const subjectHasErrors = useMemo(
    () =>
      Boolean(
        validation.commonName.error ||
        validation.organizationName.error ||
        validation.organizationalUnit.error ||
        validation.countryName.error ||
        validation.stateOrProvinceName.error ||
        validation.localityName.error,
      ),
    [validation],
  );

  const validityHasErrors = useMemo(
    () => Boolean(validation.notValidAfter.error),
    [validation.notValidAfter.error],
  );

  const canContinueFromSubject = !subjectHasErrors;
  const canContinueFromValidity = !validityHasErrors;

  const handleCATypeChange = (selfSigned: boolean) => {
    setIsSelfSigned(selfSigned);
    setFormError("");
  };

  const handleValidationChange = (
    key: keyof ValidationState,
    value: validationResult,
  ) => {
    setValidation((current) => ({
      ...current,
      [key]: value,
    }));
  };

  const handleSubmit = () => {
    mutation.mutate({
      SelfSigned: isSelfSigned ? isSelfSigned : false,
      CommonName: commonName,
      OrganizationName: organizationName,
      OrganizationalUnit: organizationalUnit,
      CountryName: countryName,
      StateOrProvinceName: stateOrProvinceName,
      LocalityName: localityName,
      NotValidAfter: notValidAfter,
    });
  };

  const goToNextStage = () => {
    if (stage === "type" && isSelfSigned !== null) {
      setStage("subject");
      return;
    }

    if (stage === "subject" && canContinueFromSubject) {
      setStage(isSelfSigned ? "validity" : "review");
      return;
    }

    if (stage === "validity" && canContinueFromValidity) {
      setStage("review");
    }
  };

  const goToPreviousStage = () => {
    if (stage === "review") {
      setStage(isSelfSigned ? "validity" : "subject");
      return;
    }

    if (stage === "validity") {
      setStage("subject");
      return;
    }

    if (stage === "subject") {
      setStage("type");
      setIsSelfSigned(null);
    }
  };

  const renderTypeStage = () => (
    <div className="p-form__group row">
      <Input
        label="Self-Signed"
        id="self-signed"
        type="radio"
        name="ca-type"
        checked={isSelfSigned === true}
        onChange={() => handleCATypeChange(true)}
        help="A self-signed certificate authority signs itself and acts as the root certificate for all other types of certificates."
      />
      <Input
        label="Intermediate"
        id="intermediate"
        type="radio"
        name="ca-type"
        checked={isSelfSigned === false}
        onChange={() => handleCATypeChange(false)}
        help="An intermediate certificate authority is signed by a root certificate authority and can sign end certificates."
      />
      <Col size={12}>
        <Button
          appearance="positive"
          onClick={(e) => {
            e.preventDefault();
            goToNextStage();
          }}
          disabled={isSelfSigned === null}
        >
          Next
        </Button>
      </Col>
    </div>
  );

  const renderSubjectStage = () => (
    <>
      <div className="p-form__group row">
        <h4>
          {isSelfSigned
            ? "Root Certificate Authority"
            : "Intermediate Certificate Authority"}
        </h4>
        <fieldset>
          <legend>Subject</legend>
          <Input
            label="Common Name"
            id="common-name"
            type="text"
            value={commonName}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setCommonName(e.target.value);
              handleValidationChange(
                "commonName",
                validateCommonName(e.target.value),
              );
            }}
            error={validation.commonName.error}
            caution={validation.commonName.caution}
            success={validation.commonName.success}
            stacked
          />
          <Input
            label="Organization Name"
            id="organization-name"
            type="text"
            value={organizationName}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setOrganizationName(e.target.value);
              handleValidationChange(
                "organizationName",
                validateOrganizationName(e.target.value),
              );
            }}
            error={validation.organizationName.error}
            caution={validation.organizationName.caution}
            success={validation.organizationName.success}
            stacked
          />
          <Input
            label="Organizational Unit"
            id="organizational-unit"
            type="text"
            value={organizationalUnit}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setOrganizationalUnit(e.target.value);
              handleValidationChange(
                "organizationalUnit",
                validateOrganizationalUnit(e.target.value),
              );
            }}
            error={validation.organizationalUnit.error}
            caution={validation.organizationalUnit.caution}
            success={validation.organizationalUnit.success}
            stacked
          />
          <Input
            label="Country Name"
            id="country-name"
            type="text"
            value={countryName}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setCountryName(e.target.value);
              handleValidationChange(
                "countryName",
                validateCountryName(e.target.value),
              );
            }}
            error={validation.countryName.error}
            caution={validation.countryName.caution}
            success={validation.countryName.success}
            stacked
          />
          <Input
            label="State or Province Name"
            id="state-or-province-name"
            type="text"
            value={stateOrProvinceName}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setStateOrProvinceName(e.target.value);
              handleValidationChange(
                "stateOrProvinceName",
                validateStateOrProvinceName(e.target.value),
              );
            }}
            error={validation.stateOrProvinceName.error}
            caution={validation.stateOrProvinceName.caution}
            success={validation.stateOrProvinceName.success}
            stacked
          />
          <Input
            label="Locality Name"
            id="locality-name"
            type="text"
            value={localityName}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setLocalityName(e.target.value);
              handleValidationChange(
                "localityName",
                validateLocalityName(e.target.value),
              );
            }}
            error={validation.localityName.error}
            caution={validation.localityName.caution}
            success={validation.localityName.success}
            stacked
          />
        </fieldset>
      </div>
      <div className="p-form__group row">
        <Col size={12}>
          <Button
            hasIcon
            onClick={(e) => {
              e.preventDefault();
              goToPreviousStage();
            }}
          >
            <i className="p-icon--chevron-left" /> <span>Prev</span>
          </Button>
          <Button
            appearance="positive"
            onClick={(e) => {
              e.preventDefault();
              goToNextStage();
            }}
            disabled={!canContinueFromSubject}
          >
            Next
          </Button>
        </Col>
      </div>
    </>
  );

  const renderValidityStage = () => (
    <>
      <div className="p-form__group row">
        <h4>Root Certificate Authority</h4>
        <fieldset>
          <legend>Validity</legend>
          <Input
            label="Not Valid After"
            id="not-valid-after"
            type="datetime-local"
            value={notValidAfter}
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              setNotValidAfter(e.target.value);
              handleValidationChange(
                "notValidAfter",
                validateNotAfter(e.target.value),
              );
            }}
            error={validation.notValidAfter.error}
            caution={validation.notValidAfter.caution}
            success={validation.notValidAfter.success}
            stacked
          />
        </fieldset>
      </div>
      <div className="p-form__group row">
        <Col size={12}>
          <Button
            hasIcon
            onClick={(e) => {
              e.preventDefault();
              goToPreviousStage();
            }}
          >
            <i className="p-icon--chevron-left" /> <span>Prev</span>
          </Button>
          <Button
            appearance="positive"
            onClick={(e) => {
              e.preventDefault();
              goToNextStage();
            }}
            disabled={!canContinueFromValidity}
          >
            Next
          </Button>
        </Col>
      </div>
    </>
  );

  const renderReviewStage = () => (
    <>
      <div className="p-form__group row">
        <h4>Review</h4>
        <p>
          <b>Certificate authority type:</b>{" "}
          {isSelfSigned
            ? "Root Certificate Authority"
            : "Intermediate Certificate Authority"}
        </p>
        <p>
          <b>Common Name:</b> {commonName || "—"}
        </p>
        <p>
          <b>Organization Name:</b> {organizationName || "—"}
        </p>
        <p>
          <b>Organizational Unit:</b> {organizationalUnit || "—"}
        </p>
        <p>
          <b>Country Name:</b> {countryName || "—"}
        </p>
        <p>
          <b>State or Province Name:</b> {stateOrProvinceName || "—"}
        </p>
        <p>
          <b>Locality Name:</b> {localityName || "—"}
        </p>
        {isSelfSigned === true ? (
          <p>
            <b>Not Valid After:</b> {notValidAfter || "—"}
          </p>
        ) : (
          <small>
            Download the Certificate Signing Request and get it signed by the
            appropriate authority. Upload the certificate at any moment using
            the action button.
          </small>
        )}
      </div>
      <div className="p-form__group row">
        {formError && (
          <Notification severity="negative" title="Error">
            {formError}
          </Notification>
        )}
        <Col size={12}>
          <Button
            hasIcon
            onClick={(e) => {
              e.preventDefault();
              goToPreviousStage();
            }}
          >
            <i className="p-icon--chevron-left" /> <span>Prev</span>
          </Button>
          {mutation.isPending ? (
            <Button appearance="positive" name="submit" disabled={true} hasIcon>
              <i className="p-icon--spinner u-animation--spin"></i>
            </Button>
          ) : (
            <Button
              appearance="positive"
              name="submit"
              onClick={(e) => {
                e.preventDefault();
                handleSubmit();
              }}
            >
              {isSelfSigned === true
                ? "Create Self Signed CA Certificate"
                : "Create Intermediate CA CSR"}
            </Button>
          )}
        </Col>
      </div>
    </>
  );

  return (
    <Panel
      title="Add a New Certificate Authority"
      controls={
        <Button onClick={() => setAsideOpen(false)} hasIcon>
          <i className="p-icon--close" />
        </Button>
      }
    >
      <Form stacked>
        {stage === "type" && renderTypeStage()}
        {stage === "subject" && renderSubjectStage()}
        {stage === "validity" && isSelfSigned === true && renderValidityStage()}
        {stage === "review" && isSelfSigned !== null && renderReviewStage()}
      </Form>
    </Panel>
  );
}
