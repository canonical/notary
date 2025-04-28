import { useMutation, useQueryClient } from "@tanstack/react-query";
import { postCA } from "@/queries";
import { ChangeEvent, useState, Dispatch, SetStateAction } from "react";
import {
  Button,
  Input,
  Panel,
  Form,
  Notification,
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
import { useAuth } from "@/hooks/useAuth";

type AsideProps = {
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
};

export default function CertificateAuthoritiesAsidePanel({
  setAsideOpen,
}: AsideProps): JSX.Element {
  const queryClient = useQueryClient();
  const auth = useAuth();

  const [isSelfSigned, setIsSelfSigned] = useState<boolean | null>(null);

  const [commonName, setCommonName] = useState<string>("");
  const [commonNameValidation, setCommonNameValidation] =
    useState<validationResult>({ error: "", caution: "", success: "" });
  const [organizationName, setOrganizationName] = useState<string>("");
  const [organizationNameValidation, setOrganizationNameValidation] =
    useState<validationResult>({ error: "", caution: "", success: "" });
  const [organizationalUnit, setOrganizationalUnit] = useState<string>("");
  const [organizationalUnitValidation, setOrganizationalUnitValidation] =
    useState<validationResult>({ error: "", caution: "", success: "" });
  const [countryName, setCountryName] = useState<string>("");
  const [countryNameValidation, setCountryNameValidation] =
    useState<validationResult>({ error: "", caution: "", success: "" });
  const [stateOrProvinceName, setStateOrProvinceName] = useState<string>("");
  const [stateOrProvinceNameValidation, setStateOrProvinceNameValidation] =
    useState<validationResult>({ error: "", caution: "", success: "" });
  const [localityName, setLocalityName] = useState<string>("");
  const [localityNameValidation, setLocalityNameValidation] =
    useState<validationResult>({ error: "", caution: "", success: "" });
  const [notValidAfter, setNotValidAfter] = useState<string>("");
  const [notValidAfterValidation, setNotValidAfterValidation] =
    useState<validationResult>({ error: "", caution: "", success: "" });
  const [formError, setFormError] = useState<string>("");

  const mutation = useMutation({
    mutationFn: postCA,
    onSuccess: () => {
      setFormError("");
      setAsideOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["cas"] });
    },
    onError: (e: Error) => {
      setFormError(e.message);
    },
  });

  const handleSubmit = () => {
    mutation.mutate({
      authToken: auth.user ? auth.user.authToken : "",

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
        {isSelfSigned === null && (
          <div className="p-form__group row">
            <Input
              label="Self-Signed"
              id="self-signed"
              type="radio"
              name="ca-type"
              checked={isSelfSigned == true}
              onChange={() => setIsSelfSigned(true)}
              help="A self-signed certificate authority signs itself and acts as the root certificate for all other types of certificates."
            />
            <Input
              label="Intermediate"
              id="self-signed"
              type="radio"
              name="ca-type"
              checked={isSelfSigned == false}
              onChange={() => setIsSelfSigned(false)}
              help="An intermediate certificate authority is signed by a root certificate authority and can sign end certificates."
            />
          </div>
        )}
        {isSelfSigned !== null && (
          <>
            <div className="p-form__group row">
              <Button hasIcon onClick={() => setIsSelfSigned(null)}>
                <i className="p-icon--chevron-left" /> <span> Back </span>
              </Button>
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
                    setCommonNameValidation(validateCommonName(e.target.value));
                  }}
                  error={commonNameValidation.error}
                  caution={commonNameValidation.caution}
                  success={commonNameValidation.success}
                  stacked
                />
                <Input
                  label="Organization Name"
                  id="organization-name"
                  type="text"
                  value={organizationName}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => {
                    setOrganizationName(e.target.value);
                    setOrganizationNameValidation(
                      validateOrganizationName(e.target.value),
                    );
                  }}
                  error={organizationNameValidation.error}
                  caution={organizationNameValidation.caution}
                  success={organizationNameValidation.success}
                  stacked
                />
                <Input
                  label="Organizational Unit"
                  id="organizational-unit"
                  type="text"
                  value={organizationalUnit}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => {
                    setOrganizationalUnit(e.target.value);
                    setOrganizationalUnitValidation(
                      validateOrganizationalUnit(e.target.value),
                    );
                  }}
                  error={organizationalUnitValidation.error}
                  caution={organizationalUnitValidation.caution}
                  success={organizationalUnitValidation.success}
                  stacked
                />
                <Input
                  label="Country Name"
                  id="country-name"
                  type="text"
                  value={countryName}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => {
                    setCountryName(e.target.value);
                    setCountryNameValidation(
                      validateCountryName(e.target.value),
                    );
                  }}
                  error={countryNameValidation.error}
                  caution={countryNameValidation.caution}
                  success={countryNameValidation.success}
                  stacked
                />
                <Input
                  label="State or Province Name"
                  id="state-or-province-name"
                  type="text"
                  value={stateOrProvinceName}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => {
                    setStateOrProvinceName(e.target.value);
                    setStateOrProvinceNameValidation(
                      validateStateOrProvinceName(e.target.value),
                    );
                  }}
                  error={stateOrProvinceNameValidation.error}
                  caution={stateOrProvinceNameValidation.caution}
                  success={stateOrProvinceNameValidation.success}
                  stacked
                />
                <Input
                  label="Locality Name"
                  id="locality-name"
                  type="text"
                  value={localityName}
                  onChange={(e: ChangeEvent<HTMLInputElement>) => {
                    setLocalityName(e.target.value);
                    setLocalityNameValidation(
                      validateLocalityName(e.target.value),
                    );
                  }}
                  error={localityNameValidation.error}
                  caution={localityNameValidation.caution}
                  success={localityNameValidation.success}
                  stacked
                />
              </fieldset>
              {isSelfSigned === true && (
                <fieldset>
                  <legend>Validity</legend>
                  <Input
                    label="Not Valid After"
                    id="not-valid-after"
                    type="datetime-local"
                    value={notValidAfter}
                    onChange={(e: ChangeEvent<HTMLInputElement>) => {
                      setNotValidAfter(e.target.value);
                      setNotValidAfterValidation(
                        validateNotAfter(e.target.value),
                      );
                    }}
                    error={notValidAfterValidation.error}
                    caution={notValidAfterValidation.caution}
                    success={notValidAfterValidation.success}
                    stacked
                  ></Input>
                </fieldset>
              )}
              {isSelfSigned === false && (
                <small>
                  Download the Certificate Signing Request and get it signed by
                  the appropriate authority. Upload the certificate at any
                  moment using the action button.
                </small>
              )}
            </div>
            <div className="p-form__group row">
              {formError && (
                <Notification severity="negative" title="Error">
                  {formError.split("error: ")}
                </Notification>
              )}
              {mutation.isPending ? (
                <Button
                  appearance="positive"
                  name="submit"
                  disabled={true}
                  hasIcon
                >
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
            </div>
          </>
        )}
      </Form>
    </Panel>
  );
}
