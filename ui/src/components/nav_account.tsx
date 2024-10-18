import { useContext, useState } from "react";
import { useAuth } from "../app/auth/authContext";
import { useCookies } from "react-cookie";
import { ChangePasswordModalContext } from "../app/(notary)/users/components";


export function AccountTab() {
  const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
  const [menuOpen, setMenuOpen] = useState<boolean>(false)
  const changePasswordModalContext = useContext(ChangePasswordModalContext)
  const authDetails = useAuth()
  return (
    <>
      {
        authDetails.user ?
          <div className="p-side-navigation__link p-contextual-menu__toggle" onClick={() => setMenuOpen(!menuOpen)} aria-current={menuOpen} style={{ cursor: "pointer" }}>
            <i className="p-icon--user is-light p-side-navigation__icon"></i>
            <span className="p-side-navigation__label">
              <span className="p-side-navigation__label">{authDetails.user.username}</span>
            </span>
            <div className="p-side-navigation__status">
              <i className="p-icon--menu"></i>
              <span className="p-contextual-menu__dropdown" id="menu-3" aria-hidden={!menuOpen} style={{ bottom: "40px" }}>
                <span className="p-contextual-menu__group">
                  <button className="p-contextual-menu__link" onMouseDown={() => changePasswordModalContext.setModalData({ "id": authDetails.user ? authDetails.user.id.toString() : "", "username": authDetails.user ? authDetails.user.username : "" })}>Change Password</button>
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
    </>)
}