"use client"
import { Strip } from "@canonical/react-components";

export default function Error({ msg }: { msg: string }) {
    return (
        <Strip >
            <p className="p-heading--5">An error occured trying to load content</p>
            <p>{msg}</p>
        </Strip>
    )
}
