import { expect, describe, it, vi } from "vitest";
import { render, fireEvent, screen } from '@testing-library/react'
import Navigation from "./nav";
import { CertificateRequestsTable } from "./certificate_requests/table";

vi.mock('next/navigation', () => ({
  usePathname: () => {
    return "/certificate_requests"
  },
}));

describe('Navigation', () => {
  it('should open aside when clicking button', () => {
    render(<Navigation><CertificateRequestsTable csrs={[]} /></Navigation>)
    const addCSRButton = screen.getByLabelText(/add-csr-button/i)
    expect(screen.getByLabelText(/aside-panel/i).className.endsWith('is-collapsed')).toBe(true)
    fireEvent.click(addCSRButton)
    expect(screen.getByLabelText(/aside-panel/i).className.endsWith('is-collapsed')).toBe(false)
  })
});