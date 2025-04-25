"use client"

import { ConfirmationModal, Notification } from "@canonical/react-components";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

export type NotaryConfirmationModalData = {
  queryFn: (params: any) => Promise<any>
  queryParams: any
  closeFn: () => void
  queryKey: string
  warningText: string
  buttonConfirmText: string
}

export function NotaryConfirmationModal(data: NotaryConfirmationModalData) {
  const [errorText, setErrorText] = useState<string>("");
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: data.queryFn,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [data.queryKey] });
      setErrorText("");
      data.closeFn();
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    }
  });
  return (
    < ConfirmationModal
      title="Confirm Action"
      confirmButtonLabel="Confirm"
      onConfirm={() => mutation.mutate(data.queryParams)}
      close={() => data.closeFn()}
    >
      <p>{data.warningText}</p>
      {errorText !== "" &&
        <Notification severity="negative" title="Error">
          {errorText}
        </Notification>
      }
    </ConfirmationModal >
  )
}