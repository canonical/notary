import { SetStateAction, Dispatch, createContext, useContext, ComponentType } from "react"

type AsideContextType = {
    isOpen: boolean,
    setIsOpen: Dispatch<SetStateAction<boolean>>
}

export const AsideContext = createContext<AsideContextType>({
    isOpen: false,
    setIsOpen: () => { },
});

export function Aside({ FormComponent, formProps }: { FormComponent: React.ComponentType<any>, formProps: any }) {
    const asideContext = useContext(AsideContext)
    return (
        <aside className={"l-aside" + (asideContext.isOpen ? "" : " is-collapsed")} id="aside-panel" aria-label="aside-panel" >
            <FormComponent {...formProps} />
        </aside >
    )
}
