"use client"

import { SetStateAction, Dispatch, useState, useContext } from "react"
import Image from "next/image";
import { useAuth } from "@/hooks/useAuth";
import { usePathname } from "next/navigation";
import { AppNavigation } from "@canonical/react-components";
import { AppNavigationBar } from "@canonical/react-components";
import { ChangePasswordModal, ChangePasswordModalContext, ChangePasswordModalData } from "@/app/(notary)/users/components";
import { useCookies } from "react-cookie";

type SidebarProps = {
  sidebarVisible: boolean,
  setSidebarVisible: Dispatch<SetStateAction<boolean>>,
  setChangePasswordModalVisible: Dispatch<SetStateAction<boolean>>
}

export function SideBar({ sidebarVisible, setSidebarVisible, setChangePasswordModalVisible }: SidebarProps) {
  const auth = useAuth()
  const path = usePathname()
  const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
  const [menuOpen, setMenuOpen] = useState<boolean>(false)

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
                    <a className="p-side-navigation__link" href="/certificate_requests" aria-current={path.startsWith("/certificate_requests") ? "page" : "false"} style={{ cursor: "pointer" }}>
                      <i className="p-icon--security is-light p-side-navigation__icon"></i>
                      <span className="p-side-navigation__label">
                        <span className="p-side-navigation__label">Certificate Requests</span>
                      </span>
                    </a>
                  </li>
                  {auth.user?.permissions == 1 &&
                    <li className="p-side-navigation__item">
                      <a className="p-side-navigation__link" href="/certificate_authorities" aria-current={path.startsWith("/certificate_authorities") ? "page" : "false"} style={{ cursor: "pointer" }}>
                        <i className="p-icon--copy-to-clipboard is-light p-side-navigation__icon"></i>
                        <span className="p-side-navigation__label">
                          <span className="p-side-navigation__label">Certificate Authorities</span>
                        </span>
                      </a>
                    </li>
                  }
                  {auth.user?.permissions == 1 &&
                    <li className="p-side-navigation__item">
                      <a className="p-side-navigation__link" href="/users" aria-current={path.startsWith("/users") ? "page" : "false"} style={{ cursor: "pointer" }}>
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
                    <>
                      {
                        auth.user ?
                          <div className="p-side-navigation__link p-contextual-menu__toggle" onClick={() => setMenuOpen(!menuOpen)} aria-current={menuOpen} style={{ cursor: "pointer" }}>
                            <i className="p-icon--user is-light p-side-navigation__icon"></i>
                            <span className="p-side-navigation__label">
                              <span className="p-side-navigation__label">{auth.user.username}</span>
                            </span>
                            <div className="p-side-navigation__status">
                              <i className="p-icon--menu"></i>
                              <span className="p-contextual-menu__dropdown" id="menu-3" aria-hidden={!menuOpen} style={{ bottom: "40px" }}>
                                <span className="p-contextual-menu__group">
                                  <button className="p-contextual-menu__link" onMouseDown={() => setChangePasswordModalVisible(true)}>Change Password</button>
                                  <button className="p-contextual-menu__link" onMouseDown={() => removeCookie("user_token")}>Log Out</button>
                                </span>
                              </span>
                            </div>
                          </div>
                          :
                          <a className="p-side-navigation__link" href="/login" aria-current="false">
                            <i className="p-icon--user is-light p-side-navigation__icon"></i>
                            <span className="p-side-navigation__label">
                              <span className="p-side-navigation__label">Login</span>
                            </span>
                          </a>
                      }
                    </>
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

export default function NotaryAppNavigationBars() {
  const auth = useAuth()
  const [sidebarVisible, setSidebarVisible] = useState<boolean>(true)
  const [changePasswordModalVisible, setChangePasswordModalVisible] = useState<boolean>(false)
  return (
    <>
      <AppNavigation>
        <SideBar sidebarVisible={sidebarVisible} setSidebarVisible={setSidebarVisible} setChangePasswordModalVisible={setChangePasswordModalVisible} />
      </AppNavigation>
      <AppNavigationBar>
        <TopBar setSidebarVisible={setSidebarVisible} />
      </AppNavigationBar>
      {changePasswordModalVisible && auth.user && <ChangePasswordModal id={auth.user.id.toString()} username={auth.user.username} setChangePasswordModalVisible={setChangePasswordModalVisible} />}
    </>
  )
}