create extension if not exists pgcrypto;

create table if not exists public.user_instances (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users (id) on delete cascade,
  email text not null,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

alter table public.user_instances enable row level security;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = timezone('utc', now());
  return new;
end;
$$;

drop trigger if exists user_instances_set_updated_at on public.user_instances;
create trigger user_instances_set_updated_at
before update on public.user_instances
for each row
execute function public.set_updated_at();

drop policy if exists "user can read own instance" on public.user_instances;
create policy "user can read own instance"
on public.user_instances
for select
to authenticated
using (
  auth.uid() = user_id
  and lower(email) like '%@threatlocker.com'
);

drop policy if exists "user can insert own instance" on public.user_instances;
create policy "user can insert own instance"
on public.user_instances
for insert
to authenticated
with check (
  auth.uid() = user_id
  and lower(email) like '%@threatlocker.com'
);

drop policy if exists "user can update own instance" on public.user_instances;
create policy "user can update own instance"
on public.user_instances
for update
to authenticated
using (
  auth.uid() = user_id
  and lower(email) like '%@threatlocker.com'
)
with check (
  auth.uid() = user_id
  and lower(email) like '%@threatlocker.com'
);
