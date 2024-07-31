import { useContext, useState, Dispatch, SetStateAction } from "react"
import { AsideContext } from "../aside"
import { UserEntry } from "../types"
import Row from "./row"

type TableProps = {
    users: UserEntry[]
}

export function UsersTable({ users: rows }: TableProps) {
    const { isOpen: isAsideOpen, setIsOpen: setAsideIsOpen } = useContext(AsideContext)
    const [actionsMenuExpanded, setActionsMenuExpanded] = useState<number>(0)
    return (
        <div className="p-panel">
            <div className="p-panel__header is-sticky">
                <h4 className="p-panel__title">Users</h4>
                <div className="p-panel__controls">
                    {rows.length > 0 && <button className="u-no-margin--bottom p-button--positive" aria-label="add-csr-button" onClick={() => setAsideIsOpen(true)}>Create New User</button>}
                </div>
            </div>
            <div className="p-panel__content">
                <div className="u-fixed-width">
                    <table id="csr-table" aria-label="Certificate Requests Table" className="p-table--expanding">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th className="has-overflow">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {
                                rows.map((row) => (
                                    <Row key={row.id} id={row.id} username={row.username} ActionMenuExpanded={actionsMenuExpanded} setActionMenuExpanded={setActionsMenuExpanded} />
                                )
                                )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}