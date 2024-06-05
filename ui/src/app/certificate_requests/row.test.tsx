import { expect, test } from 'vitest'
import { render, screen } from '@testing-library/react'
import Row from './row'

test('Certificate Requests Table Row', () => {
    render(<Row id={1} csr='' certificate='' />)
    expect(screen.getByText('1')).toBeDefined()
})
// TODO: when certificate rejected => rejected status
// TODO: when certificate empty => outstanding status
// TODO: when certificate anything else => certificate.NotAfter