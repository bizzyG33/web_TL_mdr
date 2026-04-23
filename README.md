# ThreatLocker Web Fork

This folder is a separate web fork for the existing Email Alert Generator project. It does not modify the original files in the parent directory.

## What is included

- Next.js App Router scaffold for web hosting
- Supabase browser, server, and middleware clients
- Login splash screen
- `@threatlocker.com` email restriction in the UI and protected app flow
- TOTP MFA enrollment and challenge flow
- A per-user `user_instances` table pattern for isolated app state

## Setup

1. In Supabase, enable Email/Password auth.
2. In Supabase, enable MFA with TOTP.
3. Create a `.env.local` file in `site_fork` based on `.env.example`.
4. Run the SQL in `supabase/schema.sql`.
5. Create or invite your allowed users in Supabase Auth using their `@threatlocker.com` email addresses.
6. Start the app:

```bash
npm install
npm run dev
```

## Important notes

- The app blocks non-`@threatlocker.com` addresses in the sign-in form and checks again before protected content is shown.
- This does not stop a different-domain user from existing inside Supabase Auth if they were created elsewhere. For strict tenant enforcement, keep signup invite-only or add a Supabase auth hook / admin provisioning step.
- `/app` is a placeholder dashboard shell. Replace that page with the migrated EmailAlertGenerator workflows once you decide how much of the existing desktop logic moves client-side versus server-side.

## Recommended migration path

1. Identify the current generation logic that can run safely in a server action or API route.
2. Move that logic into `site_fork` behind authenticated requests.
3. Store user-specific templates, output history, and preferences in Supabase tables with RLS.
4. Keep secrets and outbound email credentials on the server side only.
