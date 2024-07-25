import { useState, Dispatch, SetStateAction, useEffect, useRef } from "react"
import { UseMutationResult, useMutation, useQueryClient } from "react-query"
import { RequiredCSRParams, deleteUser } from "../queries"
import { ConfirmationModalData, ConfirmationModal } from "./components"
import "./../globals.scss"
import { useAuth } from "../auth/authContext"

type rowProps = {
    id: number,
    username: string,
}

export default function Row({ id, username }: rowProps) {
    const auth = useAuth()
    const [confirmationModalData, setConfirmationModalData] = useState<ConfirmationModalData>(null)
    const queryClient = useQueryClient()
    const deleteMutation = useMutation(deleteUser, {
        onSuccess: () => queryClient.invalidateQueries('users')
    })
    const mutationFunc = (mutation: UseMutationResult<any, unknown, RequiredCSRParams, unknown>, params: RequiredCSRParams) => {
        mutation.mutate(params)
    }

    const handleDelete = () => {
        setConfirmationModalData({
            onMouseDownFunc: () => mutationFunc(deleteMutation, { id: id.toString(), authToken: auth.user ? auth.user.authToken : "" }),
            warningText: "Deleting a user cannot be undone."
        })
    }

    return (
        <>
            <tr>
                <td className="" width={5} aria-label="id">{id}</td>
                <td className="" aria-label="username">{username}</td>
                <td className="" aria-label="delete-button">
                    {id == 1 ?
                        <button className="p-button--negative has-icon" onClick={handleDelete} disabled={true}><i className="p-icon--error"></i></button>
                        :
                        <button className="p-button--negative has-icon" onClick={handleDelete}><i className="p-icon--error"></i></button>
                    }
                </td>
                {confirmationModalData != null && <ConfirmationModal modalData={confirmationModalData} setModalData={setConfirmationModalData} />}
            </tr>
        </>
    )
}