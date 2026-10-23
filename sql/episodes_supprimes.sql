-- Copie complète de chaque dossier supprimé (toutes ses fiches), écrite par le serveur juste avant
-- l'effacement dans DELETE /api/episodes/:id : permet de savoir qui a supprimé quoi, quand, et de
-- restaurer. RLS activé sans policy : seul le backend (clé service_role) y accède.
create table if not exists public.episodes_supprimes (
  id uuid primary key default gen_random_uuid(),
  episode_id text not null,
  nom_patient text,
  ong_partenaire text,
  snapshot jsonb not null,
  supprime_par text,
  supprime_par_uid text,
  supprime_le timestamptz not null default now()
);
create index if not exists episodes_supprimes_episode_id_idx on public.episodes_supprimes (episode_id);
create index if not exists episodes_supprimes_supprime_le_idx on public.episodes_supprimes (supprime_le desc);
alter table public.episodes_supprimes enable row level security;
