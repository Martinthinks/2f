# Veil Authenticator

A polished, browser-only TOTP authenticator compatible with Google Authenticator and other standard `otpauth://` providers.

## Security model

- The TOTP secret is processed only in the current browser tab.
- No backend receives the TOTP secret. The app also uses no account, database, analytics, cookies, or local storage.
- Closing or refreshing the tab clears the entered secret.
- The included default secret is a public demo value and must be replaced before real use.

## Run locally

The app has no build step. Open `index.html` directly or serve the folder with any static server:

```bash
npx serve .
```

## Deploy to Vercel

1. Create a new GitHub repository and push this folder.
2. In Vercel, choose **Add New Project** and import the repository.
3. Leave **Framework Preset** as `Other` and **Build Command** empty.
4. Deploy. Vercel will serve `index.html` as the entry point.

## Supported input

- Base32 secrets, with or without spaces and padding.
- `otpauth://totp/...` links using the widely supported SHA-1 TOTP algorithm.
- 6, 7, or 8 digit codes and custom periods from 5 to 300 seconds.

## Design sources

The interface direction follows the anti-template principles from [Leonxlnx/taste-skill](https://github.com/Leonxlnx/taste-skill). The Tabler icon family was selected from the [better-auth/better-icons](https://github.com/better-auth/better-icons) catalog and loaded through Iconify's SVG endpoint, one consistent family across the page.

## License

MIT
