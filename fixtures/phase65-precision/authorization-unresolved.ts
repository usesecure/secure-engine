"use server";

export async function mutateThroughUnknownCallback(
  payload: any,
  mutation: (value: unknown) => Promise<void>,
) {
  await mutation(payload);
}
