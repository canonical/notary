import { expect, describe, it, vi } from "vitest";
import { render, fireEvent, screen } from '@testing-library/react'
import Navigation from "./nav";
import { CertificateRequestsTable } from "./certificate_requests/table";
import { User } from "./types";

vi.mock('next/navigation', () => ({
  usePathname: () => {
    return "/certificate_requests"
  },
  useRouter: () => {
    return {

    }
  }
}));
vi.mock('./auth/authContext', () => ({
  useAuth: () => {
    return { "user": { "id": 0, "username": "adman" } as User }
  }
}))

// Mock the queries module to include deleteCSR, postCSR, and getStatus
vi.mock('./queries', () => {
  return {
    getStatus: vi.fn(() => Promise.resolve({ version: "1.0.0" })),
    deleteCSR: vi.fn(() => Promise.resolve()),
    postCSR: vi.fn(() => Promise.resolve()),
    rejectCSR: vi.fn(() => Promise.resolve()),
    revokeCertificate: vi.fn(() => Promise.resolve()),
  };
});


describe('Navigation', () => {
  it('should open aside when clicking button', () => {
    render(<Navigation><CertificateRequestsTable csrs={[]} /></Navigation>)
    const addCSRButton = screen.getByLabelText(/add-csr-button/i)
    expect(screen.getByLabelText(/aside-panel/i).className.endsWith('is-collapsed')).toBe(true)
    fireEvent.click(addCSRButton)
    expect(screen.getByLabelText(/aside-panel/i).className.endsWith('is-collapsed')).toBe(false)
  })
});