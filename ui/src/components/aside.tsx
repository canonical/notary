import { SetStateAction, Dispatch, createContext, useContext } from "react"
import { useAuth } from "@/app/auth/authContext"

type AsideContextType = {
    isOpen: boolean,
    setIsOpen: Dispatch<SetStateAction<boolean>>

    extraData: any
    setExtraData: Dispatch<SetStateAction<any>>
}

export const AsideContext = createContext<AsideContextType>({
    isOpen: false,
    setIsOpen: () => { },

    extraData: null,
    setExtraData: () => { },
})

export function Aside({ FormComponent }: { FormComponent: React.ComponentType<any> }) {
    const auth = useAuth()
    const asideContext = useContext(AsideContext)
    return (
        <aside className={"l-aside" + (auth.user && asideContext.isOpen ? "" : " is-collapsed")} id="aside-panel" aria-label="aside-panel" >
            <FormComponent />
        </aside >
    )
}
