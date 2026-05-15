export type ACMEServerEntry = {
  id: number;
  name: string;
  directory_url: string;
  email: string;
  dns_provider: string;
  active: boolean;
};
