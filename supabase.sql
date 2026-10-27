-- Pawfect Homes: run this ONCE in Supabase → SQL Editor → New query → Run
create table if not exists users (
  id text primary key, name text not null, email text unique not null,
  salt text not null, hash text not null, favs text[] not null default '{}',
  created_at timestamptz not null default now());
create table if not exists sessions (
  token_hash text primary key, uid text not null references users(id) on delete cascade,
  exp timestamptz not null);
create table if not exists pets (
  id text primary key, uid text not null references users(id) on delete cascade,
  n text not null, c text, g text, t text, p text, a text, w text, l text, d text, img text,
  at timestamptz not null default now());
create table if not exists messages (
  id text primary key, pid text not null references pets(id) on delete cascade,
  from_uid text not null references users(id) on delete cascade,
  text text not null, at timestamptz not null default now());
create table if not exists posts (
  id text primary key, uid text not null references users(id) on delete cascade,
  c text, x text not null, at timestamptz not null default now());

-- Lock every table so the public (anon) key can never read or write it.
-- Only your server (using the secret key) can touch the data.
alter table users enable row level security;
alter table sessions enable row level security;
alter table pets enable row level security;
alter table messages enable row level security;
alter table posts enable row level security;

-- Public bucket for pet photos
insert into storage.buckets (id, name, public) values ('pets', 'pets', true) on conflict (id) do nothing;
