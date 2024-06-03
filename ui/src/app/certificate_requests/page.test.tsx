import { expect, test } from 'vitest'
import { render, screen } from '@testing-library/react'
import CertificateRequests from './page'

test('CertificateRequestsPage', () => {
    render(< CertificateRequests />)
    expect(screen.getByRole('table', {})).toBeDefined()
})