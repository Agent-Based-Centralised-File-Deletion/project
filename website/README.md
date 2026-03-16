# Project Website (Vercel Ready)

This folder contains a static project-submission website for the Agent-Based Centralized File Deletion System.

## Local Preview

You can open `index.html` directly in a browser, or run a simple static server:

```powershell
cd website
python -m http.server 5500
```

Then visit `http://localhost:5500`.

## Deploy to Vercel

1. Push the repository to GitHub/GitLab/Bitbucket.
2. In Vercel, create a new project and import this repository.
3. Set **Root Directory** to `website`.
4. Keep framework as **Other** (static).
5. Deploy.

The included `vercel.json` ensures route handling and static caching behavior.
