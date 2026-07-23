'use server';

export async function renameMember(form: FormData) {
  const member = String(form.get('member') ?? '');
  policy.authorizeMemberAsync(member);
  const canonical = decodeURIComponent(member).toLowerCase();
  return memberRepository.update(canonical, { state: 'active' });
}
