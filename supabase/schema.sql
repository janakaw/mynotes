-- SecretShare: public-key directory + encrypted share inbox.
-- Paste into Supabase Dashboard ▸ SQL Editor and run once.
-- Also enable: Authentication ▸ Sign In / Providers ▸ "Allow anonymous sign-ins".
--
-- The server only ever stores public keys and sealed (encrypted + signed) envelopes.
-- Expiry and view-once are enforced here AND verified by the app (expiry is signed).

-- ─── Directory ───────────────────────────────────────────────────────────────
create table if not exists public.profiles (
  user_id         uuid primary key references auth.users(id) on delete cascade,
  handle          text not null unique check (handle ~ '^[a-z0-9_]{3,20}$'),
  box_public_key  text not null check (length(box_public_key)  between 40 and 64),
  sign_public_key text not null check (length(sign_public_key) between 40 and 64),
  updated_at      timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles readable by signed-in users" on public.profiles;
create policy "profiles readable by signed-in users"
  on public.profiles for select to authenticated using (true);
-- No insert/update policies: writes only through register_profile().

-- ─── Shares (metadata only) ──────────────────────────────────────────────────
create table if not exists public.shares (
  id           uuid primary key,
  sender_id    uuid not null references public.profiles(user_id) on delete cascade,
  recipient_id uuid not null references public.profiles(user_id) on delete cascade,
  expires_at   bigint not null,                      -- unix seconds, signed by sender
  view_once    boolean not null default false,
  created_at   bigint not null default extract(epoch from now())::bigint,
  check (expires_at > created_at and expires_at <= created_at + 7 * 86400 + 300)
);
create index if not exists shares_recipient_idx on public.shares (recipient_id);
create index if not exists shares_sender_idx    on public.shares (sender_id);
create index if not exists shares_expires_idx   on public.shares (expires_at);

alter table public.shares enable row level security;

drop policy if exists "see own unexpired shares" on public.shares;
create policy "see own unexpired shares"
  on public.shares for select to authenticated
  using ((sender_id = auth.uid() or recipient_id = auth.uid())
         and expires_at > extract(epoch from now())::bigint);

drop policy if exists "sender or recipient can delete" on public.shares;
create policy "sender or recipient can delete"
  on public.shares for delete to authenticated
  using (sender_id = auth.uid() or recipient_id = auth.uid());

-- ─── Envelopes (ciphertext) — no direct access at all ────────────────────────
create table if not exists public.share_envelopes (
  share_id  uuid primary key references public.shares(id) on delete cascade,
  envelope  text not null check (length(envelope)  < 16000),  -- base64 sealed box
  signature text not null check (length(signature) < 200)     -- base64 Ed25519
);
alter table public.share_envelopes enable row level security;
-- No policies: only reachable through open_share(), so view-once can't be bypassed.

-- ─── Functions ───────────────────────────────────────────────────────────────
create or replace function public.register_profile(
  p_handle text, p_box_public_key text, p_sign_public_key text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then
    raise exception 'not signed in' using errcode = '28000';
  end if;
  insert into public.profiles (user_id, handle, box_public_key, sign_public_key)
  values (auth.uid(), lower(p_handle), p_box_public_key, p_sign_public_key)
  on conflict (user_id) do update
    set handle = excluded.handle,
        box_public_key = excluded.box_public_key,
        sign_public_key = excluded.sign_public_key,
        updated_at = now();
end; $$;

create or replace function public.send_share(
  p_id uuid, p_recipient_id uuid, p_expires_at bigint, p_view_once boolean,
  p_envelope text, p_signature text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then
    raise exception 'not signed in' using errcode = '28000';
  end if;
  insert into public.shares (id, sender_id, recipient_id, expires_at, view_once)
  values (p_id, auth.uid(), p_recipient_id, p_expires_at, p_view_once);
  insert into public.share_envelopes (share_id, envelope, signature)
  values (p_id, p_envelope, p_signature);
end; $$;

-- Recipient downloads the envelope. View-once shares are deleted in the same transaction.
create or replace function public.open_share(p_share_id uuid)
returns table (share_id uuid, sender_id uuid, recipient_id uuid, expires_at bigint,
               view_once boolean, created_at bigint, envelope text, signature text)
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
declare
  s public.shares;
  e public.share_envelopes;
begin
  select * into s from public.shares
   where public.shares.id = p_share_id
     and public.shares.recipient_id = auth.uid()
     and public.shares.expires_at > extract(epoch from now())::bigint
   for update;
  if not found then
    raise exception 'share not found' using errcode = 'P0002';
  end if;
  select * into e from public.share_envelopes where public.share_envelopes.share_id = p_share_id;
  if s.view_once then
    delete from public.shares where public.shares.id = p_share_id;  -- cascades to envelope
  end if;
  return query select s.id, s.sender_id, s.recipient_id, s.expires_at,
                      s.view_once, s.created_at, e.envelope, e.signature;
end; $$;

revoke all on function public.register_profile(text, text, text) from public, anon;
revoke all on function public.send_share(uuid, uuid, bigint, boolean, text, text) from public, anon;
revoke all on function public.open_share(uuid) from public, anon;
grant execute on function public.register_profile(text, text, text) to authenticated;
grant execute on function public.send_share(uuid, uuid, bigint, boolean, text, text) to authenticated;
grant execute on function public.open_share(uuid) to authenticated;

-- ─── Optional: purge expired rows every minute (Database ▸ Extensions ▸ enable pg_cron) ─
-- select cron.schedule('purge-expired-shares', '* * * * *',
--   $$delete from public.shares where expires_at < extract(epoch from now())::bigint$$);
