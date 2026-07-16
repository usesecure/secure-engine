import { redirect } from "next/navigation";

export function redirectThroughUnknownSelector(
  request: any,
  selector: (value: string) => string,
) {
  return redirect(selector(request.query.destination));
}
