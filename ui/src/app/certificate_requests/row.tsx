const extractCSR = (csrPemString: string) => {
    //TODO
}

const extractCert = (certPemString: string) => {
    //TODO
}

type rowProps = {
    id: number,
    csr: string,
    certificate: string
}
export default function Row({ id, csr, certificate }: rowProps) {
    return (
        <tr>
            <td className="" data-test-column="id">{id}</td>
            <td className="u-overflow--visible" data-test-column="details">
                <p>CN: example.com</p>
                <p>SAN: example.com, 127.0.0.1, 1.2.3.4.5.56</p>
            </td>
            <td className="" data-test-column="status">{certificate == "" ? "outstanding" : (certificate == "rejected" ? "rejected" : "certificate expiry date here")}</td>
            <td className="" data-test-column="action">
                <button className="p-button--positive">Sign</button>
                <button className="p-button--negative">Reject</button>
            </td>
            <td className="" data-test-column="delete">
                <button className="p-button--negative">Delete CSR</button>
            </td>
        </tr>
    )
}