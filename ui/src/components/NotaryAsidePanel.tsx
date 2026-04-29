import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Dispatch, SetStateAction, ReactElement, useState } from "react";
import {
  Icon,
  Button,
  Panel,
  useToastNotification,
  AppAside,
  Form,
} from "@canonical/react-components";

type AsideProps = {
  // Aside Panel controls
  asidePanelTitle: string;
  asidePanelIsOpen: boolean;
  setAsidePanelIsOpen: Dispatch<SetStateAction<boolean>>;
  asidePanelIsPinned?: boolean;
  setAsidePanelIsPinned?: Dispatch<SetStateAction<boolean>>;

  // Form submit actions
  formData: any; //TODO: narrow this type
  mutationFn: (formData: any) => Promise<any>;
  invalidatedQueryKeys: string[];
  mutationSuccessMessageTitle: string;
  mutationErrorMessageTitle: string;
  renderSubmitButton: (handleSubmit: () => void) => React.ReactNode;

  // Children
  children: React.ReactNode;
};

export default function NotaryAppAside({
  asidePanelIsOpen,
  setAsidePanelIsOpen,
  asidePanelIsPinned,
  setAsidePanelIsPinned,
  asidePanelTitle,

  formData,
  mutationFn,
  invalidatedQueryKeys,
  mutationSuccessMessageTitle,
  mutationErrorMessageTitle,
  renderSubmitButton,

  children,
}: AsideProps): ReactElement {
  const queryClient = useQueryClient();
  const toastNotify = useToastNotification();

  const mutation = useMutation({
    mutationFn: mutationFn,
    onSuccess: () => {
      setAsidePanelIsOpen(false);
      toastNotify.success("", [], mutationSuccessMessageTitle);
      queryClient.invalidateQueries({ queryKey: invalidatedQueryKeys });
    },
    onError: (e: Error) => {
      toastNotify.failure(mutationErrorMessageTitle, e.message);
    },
  });

  const handleSubmit = () => {
    mutation.mutate(formData);
  };
  return (
    <AppAside
      collapsed={!asidePanelIsOpen}
      pinned={asidePanelIsPinned ? asidePanelIsPinned : false}
    >
      <Panel
        title={asidePanelTitle}
        controls={
          <>
            <Button
              appearance="base"
              className="u-no-margin--bottom"
              hasIcon
              onClick={() => setAsidePanelIsOpen(false)}
            >
              <Icon name="close">Close</Icon>
            </Button>
          </>
        }
      >
        <Form stacked={true}>
          {children}
          <div className="p-form__group row">
            {renderSubmitButton(handleSubmit)}
          </div>
        </Form>
      </Panel>
    </AppAside>
  );
}
