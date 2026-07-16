import React from "react";

export function Profile({ user }) {
  return (
    <main aria-label="profile">
      <h1>{user.name}</h1>
    </main>
  );
}
