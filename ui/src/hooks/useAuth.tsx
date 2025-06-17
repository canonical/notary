"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  Dispatch,
  SetStateAction,
  useCallback,
} from "react";
import { User, CertificateAuthorityEntry } from "../types";
import { useCookies } from "react-cookie";
import { jwtDecode } from "jwt-decode";
import { useRouter } from "next/navigation";

type AuthContextType = {
  user: User | null;
  firstUserCreated: boolean;
  setFirstUserCreated: Dispatch<SetStateAction<boolean>>;
  activeCA: CertificateAuthorityEntry | null;
  setActiveCA: (value: CertificateAuthorityEntry | null) => void;
};

const AuthContext = createContext<AuthContextType>({
  user: null,
  firstUserCreated: false,
  setFirstUserCreated: () => {},
  activeCA: null,
  setActiveCA: () => {},
});

export const AuthProvider = ({
  children,
}: Readonly<{ children: React.ReactNode }>) => {
  const [cookies] = useCookies(["user_token"]);
  const [user, setUser] = useState<User | null>(null);
  const [firstUserCreated, setFirstUserCreated] = useState<boolean>(false);
  const [activeCAState, setActiveCAState] =
    useState<CertificateAuthorityEntry | null>(null);
  const router = useRouter();

  const setActiveCA = useCallback((value: CertificateAuthorityEntry | null) => {
    setActiveCAState(value);
    localStorage.setItem("activeCA", JSON.stringify(value));
  }, []);

  useEffect(() => {
    const storedActiveCA = localStorage.getItem("activeCA");
    setActiveCAState(
      storedActiveCA
        ? (JSON.parse(storedActiveCA) as CertificateAuthorityEntry)
        : null,
    );

    const token = cookies.user_token as string;
    if (token) {
      const userObject = jwtDecode<User>(token);
      userObject.authToken = token;
      setUser(userObject);
      setFirstUserCreated(true);
    } else {
      setUser(null);
      router.push("/login");
    }
  }, [cookies.user_token, router]);

  return (
    <AuthContext.Provider
      value={{
        user,
        firstUserCreated,
        setFirstUserCreated,
        activeCA: activeCAState,
        setActiveCA,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
