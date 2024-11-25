"use client"

import { passwordIsValid } from "@/utils"
import { Input, PasswordToggle, Button, Form, LoginPageLayout } from "@canonical/react-components";
import { useState, ChangeEvent } from "react"
import { useAuth } from "@/hooks/useAuth";

export default function Initialize() {
    const auth = useAuth()

    const [username, setUsername] = useState<string>("")
    const [password1, setPassword1] = useState<string>("")
    const [password2, setPassword2] = useState<string>("")
    const passwordsMatch = password1 === password2
    const password1Error = password1 && !passwordIsValid(password1) ? "Password is not valid" : ""
    const password2Error = password2 && !passwordsMatch ? "Passwords do not match" : ""

    const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => { setUsername(event.target.value) }
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <LoginPageLayout
            logo={{
                src: 'https://assets.ubuntu.com/v1/82818827-CoF_white.svg',
                title: 'Notary',
                url: '#'
            }}
            title="Initialize Notary"
        >
            <Form>
                <h4>Create the initial admin user</h4>
                <Input
                    id="InputUsername"
                    label="Username"
                    type="text"
                    required={true}
                    onChange={handleUsernameChange}
                />
                <PasswordToggle
                    help="Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
                    id="password1"
                    label="Password"
                    onChange={handlePassword1Change}
                    required={true}
                    error={password1Error}
                />
                <PasswordToggle
                    id="password2"
                    label="Confirm Password"
                    onChange={handlePassword2Change}
                    required={true}
                    error={password2Error}
                />
                <Button
                    appearance="positive"
                    disabled={!passwordsMatch || !passwordIsValid(password1)}
                    onClick={(event) => {
                        event.preventDefault();
                        if (passwordsMatch && passwordIsValid(password1)) {
                            auth.initializeFirstUser(username, password1)
                        }
                    }}
                >
                    Submit
                </Button>
            </Form>
        </LoginPageLayout>
    )
}
