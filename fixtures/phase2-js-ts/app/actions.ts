"use server";

export async function updateUser(userId: string, input: unknown) {
  const session = await authenticate();
  if (!session.user || session.user.id !== userId) {
    throw new Error("forbidden");
  }
  return database.user.update({ where: { id: userId }, data: input });
}
