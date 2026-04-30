"use client";

import {
  ConfirmationModal,
  Notification,
  useToastNotification,
} from "@canonical/react-components";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { getErrorMessage } from "@/types";

export type NotaryConfirmationModalData<T> = {
  queryFn: (params: T) => Promise<T>;
  queryParams: T;
  closeFn: () => void;
  queryKey: string;
  warningText: string;
  buttonConfirmText: string;
  successTitle?: string;
  successMessage?: string;
  failureMessage?: string;
};

export function NotaryConfirmationModal(
  // eslint-disable-next-line
  data: NotaryConfirmationModalData<any>,
) {
  const [errorText, setErrorText] = useState<string>("");
  const queryClient = useQueryClient();
  const toastNotify = useToastNotification();
  const mutation = useMutation({
    mutationFn: data.queryFn,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: [data.queryKey] });
      setErrorText("");
      toastNotify.success(
        data.successMessage ?? "The action completed successfully.",
        undefined,
        data.successTitle ?? "Action completed",
      );
      data.closeFn();
    },
    onError: (e: Error) => {
      setErrorText(getErrorMessage(e));
      toastNotify.failure(
        data.successTitle ?? "Action failed",
        e,
        data.failureMessage,
      );
    },
  });
  return (
    <ConfirmationModal
      title="Confirm Action"
      confirmButtonLabel={data.buttonConfirmText}
      onConfirm={() => mutation.mutate(data.queryParams)}
      close={() => data.closeFn()}
    >
      <p>{data.warningText}</p>
      {errorText !== "" && (
        <Notification severity="negative" title="Error">
          {errorText}
        </Notification>
      )}
    </ConfirmationModal>
  );
}
