import { useAuth } from "./auth/authContext";

export function AccountTab() {
    const authDetails = useAuth()
    return (
        <>
            {
                authDetails.user ?
                    <div className="p-side-navigation__link" aria-current="false">
                        <i className="p-icon--user is-light p-side-navigation__icon"></i>
                        <span className="p-side-navigation__label">
                            <span className="p-side-navigation__label">{authDetails.user.username}</span>
                        </span>
                        <div className="p-side-navigation__status">
                            <i className="p-icon--menu"></i>
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