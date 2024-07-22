"use client"

import { createContext, useContext, useState, useEffect } from 'react';
import { Dispatch, SetStateAction } from 'react';
import { User } from '../types';
import { useCookies } from 'react-cookie';
import { jwtDecode } from 'jwt-decode';
import { useRouter } from 'next/navigation';

type AuthContextType = {
    user: User | null
    setUser: Dispatch<SetStateAction<User | null>>
}

const AuthContext = createContext<AuthContextType>({ user: null, setUser: () => { } });

export const AuthProvider = ({ children }: Readonly<{ children: React.ReactNode }>) => {
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    const [user, setUser] = useState<User | null>(null);
    const router = useRouter();

    useEffect(() => {
        const token = cookies.user_token;
        if (token) {
            let userObject = jwtDecode(cookies.user_token) as User
            setUser(userObject);
        } else {
            router.push('/login');
        }
    }, [cookies.user_token, router]);

    return (
        <AuthContext.Provider value={{ user, setUser }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);