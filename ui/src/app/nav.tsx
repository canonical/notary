"use client"

import { SetStateAction, Dispatch, useState, createContext, useEffect, ChangeEvent } from "react"
import { QueryClient, QueryClientProvider, useMutation } from "react-query";
import Image from "next/image";
import { postCSR } from "./queries";
import { extractCSR } from "./utils";

type AsideContextType = {
    isOpen: boolean,
    setIsOpen: Dispatch<SetStateAction<boolean>>
}
export const AsideContext = createContext<AsideContextType>({ isOpen: false, setIsOpen: () => { } });

function SubmitCSR({ csrText, onClickFunc }: { csrText: string, onClickFunc: any }) {
    let csrIsValid = false
    try {
        extractCSR(csrText.trim())
        csrIsValid = true
    }
    catch (e) {
        if (e instanceof Error) {
            console.log(e.message)
        }
    }

    const validationComponent = csrText == "" ? <></> : csrIsValid ? <div><i className="p-icon--success"></i>Valid CSR</div> : <div><i className="p-icon--error"></i>Invalid CSR</div>
    const buttonComponent = csrIsValid ? <button className="p-button--positive u-float-right" name="submit" onClick={onClickFunc} >Submit</button> : <button className="p-button--positive u-float-right" name="submit" disabled={true} onClick={onClickFunc} >Submit</button>
    return (
        <>
            {validationComponent}
            {buttonComponent}
        </>
    )
}

export function Aside({ isOpen, setIsOpen }: { isOpen: boolean, setIsOpen: Dispatch<SetStateAction<boolean>> }) {
    const mutation = useMutation(postCSR, {
        onSuccess: () => {
            queryClient.invalidateQueries('csrs')
        },
    })
    const [CSRPEMString, setCSRPEMString] = useState<string>("")
    const handleTextChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
        setCSRPEMString(event.target.value);
    }
    const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0]
        if (file) {
            const reader = new FileReader();
            reader.onload = (e: ProgressEvent<FileReader>) => {
                if (e.target) {
                    if (e.target.result) {
                        setCSRPEMString(e.target.result.toString());
                    }
                }
            };
            reader.readAsText(file);
        }
    };
    return (
        <aside className={"l-aside" + (isOpen ? "" : " is-collapsed")} id="aside-panel" aria-label="aside-panel" >
            <div className="p-panel">
                <div className="p-panel__header">
                    <h4 className="p-panel__title">Add a New Certificate Request</h4>
                    <div className="p-panel__controls">
                        <button onClick={() => setIsOpen(false)} className="p-button--base u-no-margin--bottom has-icon"><i className="p-icon--close"></i></button>
                    </div>
                </div>
                <div className="p-panel__content">
                    <form className="p-form p-form--stacked">
                        <div className="p-form__group row">
                            <label htmlFor="textarea">
                                Enter or upload the CSR in PEM format below
                            </label>
                            <textarea id="csr-textarea" name="textarea" rows={10} placeholder="-----BEGIN CERTIFICATE REQUEST-----" onChange={handleTextChange} value={CSRPEMString} />
                        </div>
                        <div className="p-form__group row">
                            <input type="file" name="upload" accept=".pem,.csr" onChange={handleFileChange}></input>
                        </div>
                        <div className="p-form__group row">
                            <SubmitCSR csrText={CSRPEMString} onClickFunc={() => mutation.mutate(CSRPEMString)} />
                        </div>
                    </form>
                </div>
            </div >
        </aside >
    )
}

export function SideBar({ sidebarVisible, setSidebarVisible }: { sidebarVisible: boolean, setSidebarVisible: Dispatch<SetStateAction<boolean>> }) {
    const [activeTab, setActiveTab] = useState<string>("");
    useEffect(() => {
        if (typeof window !== 'undefined') {
            setActiveTab(location.pathname.split('/')[1]);
        }
    }, []);
    return (
        <header className={sidebarVisible ? "l-navigation" : "l-navigation is-collapsed"}>
            <div className="l-navigation__drawer">
                <div className="p-panel is-dark">
                    <div className="p-panel__header is-sticky">
                        <Logo />
                        <div className="p-panel__controls u-hide--large">
                            <button onClick={() => { setSidebarVisible(false) }} className="p-button--base is-dark has-icon u-no-margin u-hide--medium"><i className="is-light p-icon--close"></i></button>
                            <button onClick={() => { setSidebarVisible(false) }} className="p-button--base is-dark has-icon u-no-margin u-hide--small"><i className="is-light p-icon--pin"></i></button>
                        </div>
                    </div>
                    <div className="p-panel__content">
                        <div className="p-side-navigation--icons" id="drawer-icons">
                            <nav aria-label="Main">
                                <ul className="p-side-navigation__list">
                                    <li className="p-side-navigation__item">
                                        <a className="p-side-navigation__link" href="/certificate_requests" aria-current={activeTab === "certificate_requests" ? "page" : "false"} >
                                            <i className="p-icon--security is-light p-side-navigation__icon"></i>
                                            <span className="p-side-navigation__label">
                                                <span className="p-side-navigation__label">Certificate Requests</span>
                                            </span>
                                        </a>
                                    </li>
                                </ul>
                            </nav>
                        </div>
                    </div>
                </div>
            </div>
        </header >
    )
}

export function TopBar({ setSidebarVisible }: { setSidebarVisible: Dispatch<SetStateAction<boolean>> }) {
    return (
        <div className="l-navigation-bar">
            <div className="p-panel is-dark">
                <div className="p-panel__header">
                    <Logo />
                    <div className="p-panel__controls">
                        <span className="p-panel__toggle" onClick={() => { setSidebarVisible(true) }}>Menu</span>
                    </div>
                </div>
            </div>
        </div>
    )
}

export function Logo() {
    return (
        <div className="logo">
            <div className="logo-tag">
                <Image
                    src="https://assets.ubuntu.com/v1/82818827-CoF_white.svg"
                    alt="circle of friends"
                    width={32}
                    height={32}
                    className="logo-image"
                />
            </div>
            <span className="logo-text p-heading--4">GoCert</span>
        </div>
    )
}

const queryClient = new QueryClient()
export default function Navigation({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    const [sidebarVisible, setSidebarVisible] = useState<boolean>(true)
    const [asideOpen, setAsideOpen] = useState<boolean>(false)
    return (
        <QueryClientProvider client={queryClient}>
            <div className="l-application" role="presentation">
                <TopBar setSidebarVisible={setSidebarVisible} />
                <SideBar sidebarVisible={sidebarVisible} setSidebarVisible={setSidebarVisible} />
                <main className="l-main">
                    <AsideContext.Provider value={{ isOpen: asideOpen, setIsOpen: setAsideOpen }}>
                        {children}
                    </AsideContext.Provider>
                </main>
                <Aside isOpen={asideOpen} setIsOpen={setAsideOpen} />
            </div >
        </QueryClientProvider>
    )
}