import { expect, test } from 'vitest'
import { render, screen } from '@testing-library/react'
import Page from './page'

test('HomePage', () => {
    render(<Page />)
    expect(screen.getByText(/Welcome to GoCert/i)).toBeDefined()
})