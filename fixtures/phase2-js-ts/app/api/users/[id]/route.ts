import { NextResponse } from "next/server";

export async function GET(request: Request): Promise<Response> {
  const session = await authenticate(request);
  if (!session.user || !session.user.permissions.includes("users:read")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return fetch("https://example.invalid/users");
}

export async function DELETE(request: Request): Promise<Response> {
  const session = await authenticate(request);
  if (!session.user) {
    return new Response(null, { status: 403 });
  }
  return new Response(null, { status: 204 });
}
