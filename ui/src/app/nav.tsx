"use client"

import { SetStateAction, Dispatch, useState, useEffect } from "react"
import { QueryClient, QueryClientProvider } from "react-query";
import Image from "next/image";
import { Aside, AsideContext } from "./aside";
import { AccountTab } from "./login"

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
                                <ul className="p-side-navigation__list" style={{ bottom: 0, position: "absolute", width: "100%" }}>
                                    <li className="p-side-navigation__item" >
                                        <AccountTab />
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