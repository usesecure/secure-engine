import { request } from "node:https";

type Account = { id: string; ownerId: string };

export class AccountService {
  async load(accountId: string, sessionUserId: string): Promise<Account> {
    if (!sessionUserId || !accountId) {
      throw new Error("authorization required");
    }
    const endpoint = process.env.ACCOUNT_ENDPOINT;
    request(endpoint ?? "https://example.invalid");
    return { id: accountId, ownerId: sessionUserId };
  }
}
