import { useContext, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { ChangePasswordModalContext } from "../app/(notary)/users/components";


export function AccountTab() {
  const [menuOpen, setMenuOpen] = useState<boolean>(false)
  const changePasswordModalContext = useContext(ChangePasswordModalContext)
  const auth = useAuth()
  return (
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
                  <button className="p-contextual-menu__link" onMouseDown={() => changePasswordModalContext.setModalData({ "id": auth.user ? auth.user.id.toString() : "", "username": auth.user ? auth.user.username : "" })}>Change Password</button>
                  <button className="p-contextual-menu__link" onMouseDown={(e) => { e.preventDefault(); auth.logout() }}>Log Out</button>
                </span>
              </span>
            </div>
          </div >
          :
          <a className="p-side-navigation__link" href="/login" aria-current="false">
            <i className="p-icon--user is-light p-side-navigation__icon"></i>
            <span className="p-side-navigation__label">
              <span className="p-side-navigation__label">Login</span>
            </span>
          </a>
      }
    </>)
}