import { Dispatch, SetStateAction } from "react"
import { ConfirmationModalData } from "./row"

interface ConfirmationModalProps {
    modalData: ConfirmationModalData
    setModalData: Dispatch<SetStateAction<ConfirmationModalData>>
}


export function ConfirmationModal({ modalData, setModalData }: ConfirmationModalProps) {
    const confirmQuery = () => {
        modalData?.func()
        setModalData(null)
    }
    return (
        <div className="p-modal" id="modal">
            <section className="p-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-description">
                <header className="p-modal__header">
                    <h2 className="p-modal__title" id="modal-title">Confirm Action</h2>
                </header>
                <p>{modalData?.warningText}</p>
                <footer className="p-modal__footer">
                    <button className="u-no-margin--bottom" aria-controls="modal" onMouseDown={() => setModalData(null)}>Cancel</button>
                    <button className="p-button--negative u-no-margin--bottom" onMouseDown={confirmQuery}>Confirm</button>
                </footer>
            </section>
        </div>
    )
}

export function SuccessNotification({ successMessage }: { successMessage: string }) {
    const style = {
        display: 'inline'
    }
    return (
        <p style={style}>
            <i className="p-icon--success"></i> {successMessage}
        </p>
    );
}