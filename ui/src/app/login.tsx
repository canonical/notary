import { jwtDecode } from "jwt-decode";
import { useState } from "react";
import { useCookies } from "react-cookie"

type UserObject = {
    exp: number
    id: number
    permissions: number
    username: string
}

export function Login() {
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    var userObject: UserObject | null = null
    if (cookies.user_token) {
        userObject = jwtDecode(cookies.user_token)
    }
    return (
        <>
            {
                cookies.user_token ? <p>{userObject?.username}</p> : <a className="p-button u-float-right" style={{ marginRight: "5px" }} href="login">Login</a>
            }
        </>)
}