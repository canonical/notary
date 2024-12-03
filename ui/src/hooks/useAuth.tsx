"use client"

import { createContext, useContext, useState, useEffect, useCallback, Dispatch, SetStateAction, useMemo } from 'react';
import { User } from '../types';
import { useCookies } from 'react-cookie';
import { jwtDecode } from 'jwt-decode';
import { useRouter } from 'next/navigation';
import { useMutation } from '@tanstack/react-query';
import { postFirstUser } from '@/queries';

type AuthContextType = {
  user: User | null

  login: (token: string) => void
  logout: () => void

  firstUserInitialized: boolean | "unknown"
  setFirstUserInitialized: Dispatch<SetStateAction<boolean | "unknown">>

  initializeFirstUser: (username: string, password: string) => void
  initializationError: string
}

const AuthContext = createContext<AuthContextType>({
  user: null,

  login: (token: string) => { },
  logout: () => { },

  firstUserInitialized: false,
  setFirstUserInitialized: () => { },

  initializeFirstUser: (username, password) => { },
  initializationError: ""
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }: Readonly<{ children: React.ReactNode }>) => {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [cookies, setCookie, removeCookie] = useCookies(['user_token']);

  // This section handles login/logout
  const login = useCallback((value: string) => {
    setCookie('user_token', value,
      {
        sameSite: true,
        secure: true,
        expires: new Date(new Date().getTime() + 60 * 60 * 1000),
      }
    )
  }, [setCookie])
  const logout = useCallback(() => {
    removeCookie('user_token')
  }, [removeCookie])

  // This section deals with initialization
  const [firstUserInitialized, setFirstUserInitialized] = useState<boolean | "unknown">("unknown")
  const [initializationError, setInitializationError] = useState<string>("")
  const postUserMutation = useMutation({
    mutationFn: postFirstUser,
    onSuccess: () => {
      setInitializationError("")
      setFirstUserInitialized(true)
    },
    onError: (e: Error) => {
      setInitializationError(e.message)
    }
  })
  const initializeFirstUser = useCallback((username: string, password: string) => { postUserMutation.mutate({ username: username, password: password }) }, [postUserMutation])

  // This hook coordinates the frontend depending on the login and initialization state of the app
  useEffect(() => {
    const token = cookies.user_token;
    if (token) {
      let userObject = jwtDecode(cookies.user_token) as User
      userObject.authToken = cookies.user_token
      setUser(userObject);
      return
    }
    if (!token) {
      router.push('/login')
    }
    if (firstUserInitialized == false) {
      router.push('/initialize')
    }
  }, [cookies.user_token, router, firstUserInitialized]);

  return (
    <AuthContext.Provider value={{ user, login, logout, firstUserInitialized, setFirstUserInitialized, initializeFirstUser, initializationError }}>
      {children}
    </AuthContext.Provider >
  );
};
