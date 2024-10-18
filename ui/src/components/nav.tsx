"use client"

import { SetStateAction, Dispatch, useState, useEffect } from "react"
import { useQuery } from "@tanstack/react-query";
import Image from "next/image";
import { Aside, AsideContext } from "./aside";
import { AccountTab } from "./nav_account"
import { usePathname } from "next/navigation";
import { useAuth } from "../app/auth/authContext";
import UploadCSRAsidePanel from "../app/(notary)/certificate_requests/asideForm";
import UploadUserAsidePanel from "../app/(notary)/users/asideForm";
import { getStatus } from "@/queries"
import { ChangePasswordModalData, ChangePasswordModal, ChangePasswordModalContext } from "../app/(notary)/users/components";

export function SideBar({ activePath, sidebarVisible, setSidebarVisible }: { activePath: string, sidebarVisible: boolean, setSidebarVisible: Dispatch<SetStateAction<boolean>> }) {
  const auth = useAuth()
  const statusQuery = useQuery({
    queryKey: ["status"],
    queryFn: getStatus,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    refetchOnReconnect: false,
  })

  return (
    <header className={sidebarVisible ? "l-navigation" : "l-navigation is-collapsed"} >
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
                    <a className="p-side-navigation__link" href="/certificate_requests" aria-current={activePath.startsWith("/certificate_requests") ? "page" : "false"} style={{ cursor: "pointer" }}>
                      <i className="p-icon--security is-light p-side-navigation__icon"></i>
                      <span className="p-side-navigation__label">
                        <span className="p-side-navigation__label">Certificate Requests</span>
                      </span>
                    </a>
                  </li>
                  {auth.user?.permissions == 1 &&
                    <li className="p-side-navigation__item">
                      <a className="p-side-navigation__link" href="/users" aria-current={activePath.startsWith("/users") ? "page" : "false"} style={{ cursor: "pointer" }}>
                        <i className="p-icon--user is-light p-side-navigation__icon"></i>
                        <span className="p-side-navigation__label">
                          <span className="p-side-navigation__label">Users</span>
                        </span>
                      </a>
                    </li>
                  }
                </ul>
                <ul className="p-side-navigation__list" style={{ bottom: "64px", position: "absolute", width: "100%" }}>
                  <li className="p-side-navigation__item" >
                    <AccountTab />
                  </li>
                </ul>
                <ul className="p-side-navigation__list" style={{ bottom: 0, position: "absolute", width: "100%" }}>
                  <li className="p-side-navigation__item">
                    <span className="p-side-navigation__text">
                      Version {statusQuery.data?.version}
                    </span>
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
      <span className="logo-text p-heading--4">Notary</span>
    </div>
  )
}

export default function Navigation({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const activePath = usePathname()

  const [sidebarVisible, setSidebarVisible] = useState<boolean>(true)
  const [asideOpen, setAsideOpen] = useState<boolean>(false)
  const [asideData, setAsideData] = useState<any>(null)
  const [changePasswordModalData, setChangePasswordModalData] = useState<ChangePasswordModalData>(null)
  let asideForm = UploadCSRAsidePanel
  if (activePath == "/users") {
    asideForm = UploadUserAsidePanel
  }
  return (
    <div className="l-application" role="presentation">
      <AsideContext.Provider value={{ isOpen: asideOpen, setIsOpen: setAsideOpen, extraData: asideData, setExtraData: setAsideData }}>
        <ChangePasswordModalContext.Provider value={{ modalData: changePasswordModalData, setModalData: setChangePasswordModalData }}>
          <TopBar setSidebarVisible={setSidebarVisible} />
          <SideBar activePath={activePath} sidebarVisible={sidebarVisible} setSidebarVisible={setSidebarVisible} />
        </ChangePasswordModalContext.Provider>
        <main className="l-main">
          {children}
          {changePasswordModalData != null && <ChangePasswordModal modalData={changePasswordModalData} setModalData={setChangePasswordModalData} />}
        </main>
        <Aside FormComponent={asideForm} />
      </AsideContext.Provider>
    </div >
  )
}