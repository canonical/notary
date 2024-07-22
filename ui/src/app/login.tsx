import { useAuth } from "./auth/authContext";

export function AccountTab() {
    const authDetails = useAuth()
    return (
        <>
            {
                authDetails.user ?
                    <div className="p-side-navigation__item" aria-current="false">
                        <i className="p-icon--user is-light p-side-navigation__icon"></i>
                        <span className="p-side-navigation__label">
                            <span className="p-side-navigation__label">{authDetails.user.username}</span>
                        </span>
                        <i className="p-icon--menu" style={{ marginLeft: "auto", marginTop: "auto", marginBottom: "auto" }}></i>
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