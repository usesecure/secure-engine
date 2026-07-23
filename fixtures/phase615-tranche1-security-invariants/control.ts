'use server';

export async function renameMember(form: FormData) {
  const member = String(form.get('member') ?? '');
  const canonical = decodeURIComponent(member).toLowerCase();
  await policy.authorizeMemberAsync(canonical);
  return memberRepository.update(canonical, { state: 'active' });
}
