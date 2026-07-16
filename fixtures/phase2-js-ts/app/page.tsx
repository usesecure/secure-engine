import { Profile } from "../src/component";

export default async function Page() {
  const user = await loadUser();
  return <Profile user={user} />;
}
