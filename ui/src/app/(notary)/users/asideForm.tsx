import { useMutation, useQueryClient } from "@tanstack/react-query";
import { passwordIsValid } from "@/utils";
import { changePassword, postUser } from "@/queries";
import { ChangeEvent, useContext, useState } from "react";
import { AsideContext } from "@/components/aside";
import { useAuth } from "@/app/auth/authContext";
import { Panel, Button, Input, PasswordToggle, Form } from "@canonical/react-components";

export default function UsersPageAsidePanel() {
    const asideContext = useContext(AsideContext)
    const panelTitle = asideContext.extraData == null ? "Add a New User" : "Change User Password"
    return (
        <Panel
            title={panelTitle}
            controls={
                <Button
                    onClick={() => asideContext.setIsOpen(false)}
                    hasIcon>
                    <i className="p-icon--close" />
                </Button>
            }>
            {asideContext.extraData == null ? (
                <AddNewUserForm />
            ) : (
                <ChangePasswordForm />
            )}
        </Panel>
    )
}


function AddNewUserForm() {
    const auth = useAuth()
    const queryClient = useQueryClient()
    const asideContext = useContext(AsideContext)
    const mutation = useMutation({
        mutationFn: postUser,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] })
            setErrorText("")
            asideContext.setIsOpen(false)
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const [username, setUsername] = useState<string>("")
    const [password1, setPassword1] = useState<string>("")
    const [password2, setPassword2] = useState<string>("")
    const passwordsMatch = password1 === password2
    const password1Error = password1 && !passwordIsValid(password1) ? "Password is not valid" : ""
    const password2Error = password2 && !passwordsMatch ? "Passwords do not match" : ""

    const [errorText, setErrorText] = useState<string>("")
    const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => { setUsername(event.target.value) }
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <Form>
            <div className="p-form__group row">
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
                    label="Password"
                    onChange={handlePassword2Change}
                    required={true}
                    error={password2Error}
                />
                <Button
                    appearance="positive"
                    disabled={!passwordsMatch || !passwordIsValid(password1)}
                    onClick={(event) => { event.preventDefault(); mutation.mutate({ authToken: (auth.user ? auth.user.authToken : ""), username: username, password: password1 }) }}
                >
                    Submit
                </Button>
            </div>
        </Form>
    )
}

function ChangePasswordForm() {
    const auth = useAuth()
    const asideContext = useContext(AsideContext)
    const queryClient = useQueryClient()
    const mutation = useMutation({
        mutationFn: changePassword,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] })
            setErrorText("")
            asideContext.setIsOpen(false)
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const [password1, setPassword1] = useState<string>("")
    const [password2, setPassword2] = useState<string>("")
    const passwordsMatch = password1 === password2
    const password1Error = password1 && !passwordIsValid(password1) ? "Password is not valid" : ""
    const password2Error = password2 && !passwordsMatch ? "Passwords do not match" : ""

    const [errorText, setErrorText] = useState<string>("")
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <Form>
            <div className="p-form__group row">
                <Input
                    id="InputUsername"
                    label="Username"
                    type="text"
                    value={asideContext.extraData["user"]["username"]}
                    disabled={true}
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
                    label="Password"
                    onChange={handlePassword2Change}
                    required={true}
                    error={password2Error}
                />
                <Button
                    appearance="positive"
                    disabled={!passwordsMatch || !passwordIsValid(password1)}
                    onClick={(event) => { event.preventDefault(); mutation.mutate({ authToken: (auth.user ? auth.user.authToken : ""), id: asideContext.extraData["user"]["id"], password: password1 }) }}
                >
                    Submit
                </Button>
            </div>
        </Form>
    )
}
