import { useCallback, useEffect, useState } from "react";
import { CertificateAuthorityEntry } from "@/types";

type CertificateAuthoritySetter = (
  value: CertificateAuthorityEntry | null,
) => void;

export function useActiveCA(): [
  CertificateAuthorityEntry | null,
  CertificateAuthoritySetter,
] {
  const [_activeCAState, _setActiveCAState] =
    useState<CertificateAuthorityEntry | null>(null);

  const setActiveCA = useCallback((value: CertificateAuthorityEntry | null) => {
    _setActiveCAState(value);
    localStorage.setItem("activeCA", JSON.stringify(value));
  }, []);

  useEffect(() => {
    const storedActiveCA = localStorage.getItem("activeCA");
    _setActiveCAState(
      storedActiveCA
        ? (JSON.parse(storedActiveCA) as CertificateAuthorityEntry)
        : null,
    );
  }, []);

  return [_activeCAState, setActiveCA];
}
