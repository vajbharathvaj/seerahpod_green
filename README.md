
  # Design seerahPod Admin Panel

  This is a code bundle for Design seerahPod Admin Panel. The original project is available at https://www.figma.com/design/QbkMN7VxDaP8ZrIaMpGR9q/Design-seerahPod-Admin-Panel.

  ## Running the code

  Run `npm i` to install the dependencies.

  Run `npm run dev` to start the development server.

  ## Vercel build note

  Vercel can return `Permission denied` when executing the `node_modules/.bin/vite` shim.
  The build script uses a direct Node invocation to avoid this:

  ```bash
  node ./node_modules/vite/bin/vite.js build
  ```
  
